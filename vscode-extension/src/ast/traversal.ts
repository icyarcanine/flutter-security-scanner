import type { SyntaxNode } from 'web-tree-sitter';

type AstNode = SyntaxNode | any;

/**
 * Maximum AST depth we'll walk before bailing. Tree-sitter ASTs of heavily
 * minified single-line JS can reach tens of thousands of nested nodes, which
 * blows Node's default call stack (~10k frames). The iterative walker below
 * also enforces this as a safety net against pathological input.
 */
const MAX_AST_WALK_DEPTH = 8000;

/**
 * Iterative pre-order AST walk. Calls `callback(node)` on every node.
 * If the callback returns `false`, that subtree is skipped (matches the
 * recursive variant's contract).
 *
 * Iterative rather than recursive to avoid stack overflow on deeply-nested
 * minified files. Hard-capped at MAX_AST_WALK_DEPTH for the same reason —
 * if a tree somehow exceeds that depth we just stop descending; the rules
 * that drove the walk can still report on what they've already seen.
 */
export function walkAst(node: AstNode, callback: (node: AstNode) => void | false) {
  // Stack carries [node, depth] pairs. We push children in reverse so the
  // pre-order traversal yields children left-to-right.
  const stack: Array<[AstNode, number]> = [[node, 0]];
  while (stack.length > 0) {
    const top = stack.pop();
    if (!top) { break; }
    const [current, depth] = top;
    if (callback(current) === false) { continue; }
    if (depth >= MAX_AST_WALK_DEPTH) { continue; }
    const count = namedChildCount(current);
    for (let i = count - 1; i >= 0; i--) {
      const child = namedChild(current, i);
      if (child) { stack.push([child, depth + 1]); }
    }
  }
}

export function findNodesByType(root: AstNode, type: string | string[]): AstNode[] {
  const result: AstNode[] = [];
  const targetTypes = Array.isArray(type) ? type : [type];

  walkAst(root, (node) => {
    if (targetTypes.includes(node.type)) {
      result.push(node);
    }
  });

  return result;
}

export function isAssignment(node: AstNode): boolean {
  return [
    'assignment_expression', // JS, TS, Java
    'augmented_assignment_expression', // JS, TS (e.g. `x += y`)
    'assignment',            // Python, Go
    'variable_declarator',   // JS, Java
    'short_var_declaration', // Go
    'augmented_assignment',   // Python
    'initialized_variable_definition', // Dart
  ].includes(node.type);
}

/**
 * True if the assignment is "augmented" (e.g. `x += y`, `x |= y`). For these
 * the right-hand side is concatenated with / combined into the left, so taint
 * tracking must be additive: if RHS is tainted, mark LHS tainted, but never
 * clear LHS taint just because RHS is a literal.
 */
export function isAugmentedAssignment(node: AstNode): boolean {
  return [
    'augmented_assignment_expression',
    'augmented_assignment',
  ].includes(node.type);
}

export function isFunctionCall(node: AstNode): boolean {
  if (node.type === 'expression_statement' && getDartCallArgumentsNode(node) != null) {
    return true;
  }

  return [
    'call_expression',     // JS, TS, Go
    'call',                // Python, Ruby
    'new_expression',      // JS constructors like new Function(...)
    'method_invocation',   // Java
    'constructor_invocation', // Dart
  ].includes(node.type);
}

export function isFunctionScope(node: AstNode): boolean {
  return [
    'function_declaration',
    'function',
    'function_definition',
    'method_declaration',
    'method_definition',
    'arrow_function',
    'generator_function_declaration',
    'func_literal',
    'function_body',
    'local_function_declaration',
    'lambda_expression',
    'program',
    'source_file',
  ].includes(node.type);
}

// Note: `_lang` is part of the public signature for future per-language
// extraction differences but is currently unused.
export function getAssignmentNames(node: AstNode, _lang: string): string[] {
  // This extracts LHS of assignments to track what gets tainted
  const names: string[] = [];
  if (['assignment_expression', 'assignment',
       'augmented_assignment_expression', 'augmented_assignment'].includes(node.type)) {
    const left = childForFieldName(node, 'left');
    if (left) names.push(...extractBindingNames(left));
  } else if (node.type === 'variable_declarator') {
    const name = childForFieldName(node, 'name');
    if (name) names.push(...extractBindingNames(name));
  } else if (node.type === 'initialized_variable_definition') {
    const name = childForFieldName(node, 'name');
    if (name?.text) names.push(name.text);
  } else if (node.type === 'short_var_declaration') {
    const left = childForFieldName(node, 'left');
    // Go might have multiple, like `a, b := 1, 2`
    if (left) {
      for (const child of namedChildren(left)) {
        if (child.type === 'identifier') names.push(child.text);
      }
    }
  }
  return names;
}

/**
 * Extract identifier names from a binding pattern. Handles:
 *   - bare identifier: `x` -> ['x']
 *   - object pattern: `{ a, b: c }` -> ['a', 'c']
 *   - array pattern: `[a, b]` -> ['a', 'b']
 *   - rest element: `...rest` -> ['rest']
 *   - default value: `{ a = 1 }` -> ['a']
 *   - nested: `{ a: { b } }` -> ['b']
 *
 * Falls back to the raw text for unrecognized patterns so simple
 * identifiers continue to round-trip exactly as before.
 */
function extractBindingNames(node: AstNode): string[] {
  if (!node) return [];

  if (node.type === 'identifier' || node.type === 'shorthand_property_identifier_pattern') {
    return [node.text];
  }

  // Object/array destructuring patterns — recurse into named children
  if (node.type === 'object_pattern' || node.type === 'array_pattern' ||
      node.type === 'tuple_pattern' || node.type === 'list_pattern') {
    const out: string[] = [];
    for (let i = 0; i < namedChildCount(node); i++) {
      const child = namedChild(node, i);
      if (child) out.push(...extractBindingNames(child));
    }
    return out;
  }

  // pair_pattern { key: value } — the value is the binding
  if (node.type === 'pair_pattern') {
    const value = childForFieldName(node, 'value');
    if (value) return extractBindingNames(value);
  }

  // object_assignment_pattern { x = default } — the LEFT side is the binding,
  // the right side is the default value (which we discard).
  if (node.type === 'object_assignment_pattern') {
    const left = childForFieldName(node, 'left') ?? namedChild(node, 0);
    if (left) return extractBindingNames(left);
  }

  // assignment_pattern (destructure with default): { x = 1 }
  if (node.type === 'assignment_pattern') {
    const left = childForFieldName(node, 'left') ?? namedChild(node, 0);
    if (left) return extractBindingNames(left);
  }

  // rest_pattern / spread_element
  if (node.type === 'rest_pattern' || node.type === 'rest_element' || node.type === 'spread_element') {
    const inner = namedChild(node, 0);
    if (inner) return extractBindingNames(inner);
  }

  // Fallback: return the raw text so simple identifiers still work,
  // and unrecognized patterns are passed through to _normalizeSymbol
  // (which will reject anything non-identifier-shaped).
  return node.text ? [node.text] : [];
}

export function getAssignmentValue(node: AstNode): AstNode | null {
  return childForFieldName(node, 'right') ??
    childForFieldName(node, 'value') ??
    (namedChildCount(node) > 1 ? namedChild(node, namedChildCount(node) - 1) : null) ??
    null;
}

export function getCallTarget(node: AstNode): AstNode | null {
  return childForFieldName(node, 'function') ??
    childForFieldName(node, 'name') ??
    namedChild(node, 0) ??
    null;
}

export function getCallName(node: AstNode): string {
  const dartName = getDartCallName(node);
  if (dartName) {
    return dartName;
  }

  const target = getCallTarget(node);
  return target?.text.replace(/\s+/g, '') ?? '';
}

export function getCallArguments(node: AstNode): AstNode[] {
  const dartArgs = getDartCallArgumentsNode(node);
  const args = dartArgs ??
    childForFieldName(node, 'arguments') ??
    children(node).find((c: AstNode) =>
      ['arguments', 'argument_list', 'formal_parameters'].includes(c.type));
  if (!args) { return []; }
  return namedChildren(args).filter((child: AstNode) => child.type !== ',' && child.type !== ';');
}

export function getFunctionParameterNames(node: AstNode): string[] {
  const signature = node.type === 'function_body'
    ? previousNamedSibling(node)
    : node;
  const params = childForFieldName(signature, 'parameters') ??
    children(signature).find((c: AstNode) =>
      ['formal_parameters', 'parameters', 'parameter_list', 'formal_parameter_list'].includes(c.type)) ??
    findFirstDescendantByType(signature, ['formal_parameters', 'parameters', 'parameter_list', 'formal_parameter_list']);
  if (!params) { return []; }

  const names: string[] = [];
  walkAst(params, (child) => {
    if (child === params) { return; }
    if (child.type === 'identifier' || child.type === 'shorthand_property_identifier_pattern') {
      names.push(child.text);
      return;
    }

    const nameField = childForFieldName(child, 'name');
    if (nameField?.type === 'identifier') {
      names.push(nameField.text);
    }
  });
  return Array.from(new Set(names));
}

export interface ParameterSlot {
  /** Names bound by this parameter slot. Multiple names imply destructuring. */
  names: string[];
  /** True if the parameter was a destructuring pattern (object/array/tuple). */
  destructured: boolean;
}

/**
 * Returns the parameter slots of a function. Each slot represents one
 * positional parameter and tracks whether it was destructured.
 *
 * Examples:
 *   `(req, res)`           -> [{names:['req'], destructured:false}, {names:['res'], destructured:false}]
 *   `({ query, body })`    -> [{names:['query','body'], destructured:true}]
 *   `({ query }, res)`     -> [{names:['query'], destructured:true}, {names:['res'], destructured:false}]
 *
 * Used by the taint engine to recognize destructured request handlers,
 * where the inner names (`query`/`body`/etc.) inherit taint from the
 * implicit request parameter slot — but a bare `function f(query)` does not.
 */
export function getFunctionParameterGroups(node: AstNode): ParameterSlot[] {
  const signature = node.type === 'function_body'
    ? previousNamedSibling(node)
    : node;
  const params = childForFieldName(signature, 'parameters') ??
    children(signature).find((c: AstNode) =>
      ['formal_parameters', 'parameters', 'parameter_list', 'formal_parameter_list'].includes(c.type)) ??
    findFirstDescendantByType(signature, ['formal_parameters', 'parameters', 'parameter_list', 'formal_parameter_list']);
  if (!params) { return []; }

  const slots: ParameterSlot[] = [];
  for (const param of namedChildren(params)) {
    if (param.type === ',' || param.type === ';') { continue; }

    // Direct identifier parameter
    if (param.type === 'identifier') {
      slots.push({ names: [param.text], destructured: false });
      continue;
    }

    // Destructuring pattern directly in slot
    if (param.type === 'object_pattern' || param.type === 'array_pattern' ||
        param.type === 'tuple_pattern' || param.type === 'list_pattern') {
      slots.push({ names: extractBindingNames(param), destructured: true });
      continue;
    }

    // Default value wrapper: `({ query = {} } = {})` parses as
    // `assignment_pattern { left: object_pattern, right: object }`. We need
    // to treat the inner pattern as destructured even though it isn't the
    // outermost node.
    if (param.type === 'assignment_pattern') {
      const left = childForFieldName(param, 'left') ?? namedChild(param, 0);
      if (left && (
        left.type === 'object_pattern' || left.type === 'array_pattern' ||
        left.type === 'tuple_pattern' || left.type === 'list_pattern'
      )) {
        slots.push({ names: extractBindingNames(left), destructured: true });
        continue;
      }
      if (left && left.type === 'identifier') {
        slots.push({ names: [left.text], destructured: false });
        continue;
      }
    }

    // Common wrappers: required_parameter, optional_parameter, parameter, etc.
    const innerName = childForFieldName(param, 'name') ??
      childForFieldName(param, 'pattern') ??
      param;

    if (innerName && (
      innerName.type === 'object_pattern' ||
      innerName.type === 'array_pattern' ||
      innerName.type === 'tuple_pattern' ||
      innerName.type === 'list_pattern'
    )) {
      slots.push({ names: extractBindingNames(innerName), destructured: true });
      continue;
    }

    if (innerName && innerName.type === 'identifier') {
      slots.push({ names: [innerName.text], destructured: false });
      continue;
    }

    // Fallback: collect any identifier-shaped descendants. Treat as
    // non-destructured since we can't be sure of the structure.
    const collected: string[] = [];
    walkAst(param, (child) => {
      if (child.type === 'identifier' || child.type === 'shorthand_property_identifier_pattern') {
        collected.push(child.text);
      }
    });
    if (collected.length > 0) {
      slots.push({ names: collected, destructured: collected.length > 1 });
    }
  }
  return slots;
}

export function childForFieldName(node: AstNode | null | undefined, fieldName: string): AstNode | null {
  if (!node) { return null; }
  if (typeof node.childForFieldName === 'function') {
    return node.childForFieldName(fieldName) ?? null;
  }

  const singularProp = `${fieldName}Node`;
  const pluralProp = `${fieldName}Nodes`;
  if (node[singularProp]) {
    return node[singularProp];
  }
  if (Array.isArray(node[pluralProp]) && node[pluralProp].length > 0) {
    return node[pluralProp][0];
  }

  if (fieldName === 'value' && Array.isArray(node.valueNodes) && node.valueNodes.length > 0) {
    return node.valueNodes[0];
  }
  if (fieldName === 'right' && Array.isArray(node.rightNodes) && node.rightNodes.length > 0) {
    return node.rightNodes[0];
  }
  if (fieldName === 'left' && node.leftNode) {
    return node.leftNode;
  }
  if (fieldName === 'name' && node.nameNode) {
    return node.nameNode;
  }

  return null;
}

export function children(node: AstNode | null | undefined): AstNode[] {
  if (!node) { return []; }
  return Array.isArray(node.children) ? node.children : [];
}

export function namedChildren(node: AstNode | null | undefined): AstNode[] {
  if (!node) { return []; }
  if (Array.isArray(node.namedChildren)) {
    return node.namedChildren;
  }
  const count = namedChildCount(node);
  const result: AstNode[] = [];
  for (let i = 0; i < count; i++) {
    const child = namedChild(node, i);
    if (child) {
      result.push(child);
    }
  }
  return result;
}

export function namedChildCount(node: AstNode | null | undefined): number {
  if (!node) { return 0; }
  if (typeof node.namedChildCount === 'number') {
    return node.namedChildCount;
  }
  return Array.isArray(node.namedChildren) ? node.namedChildren.length : 0;
}

export function namedChild(node: AstNode | null | undefined, index: number): AstNode | null {
  if (!node) { return null; }
  if (typeof node.namedChild === 'function') {
    return node.namedChild(index) ?? null;
  }
  return namedChildren(node)[index] ?? null;
}

function previousNamedSibling(node: AstNode | null | undefined): AstNode | null {
  if (!node) { return null; }
  if (node.previousNamedSibling) {
    return node.previousNamedSibling;
  }
  const parent = node.parent;
  if (!parent) { return null; }
  const siblings = namedChildren(parent);
  const index = siblings.indexOf(node);
  return index > 0 ? siblings[index - 1] : null;
}

function findFirstDescendantByType(node: AstNode | null | undefined, types: string | string[]): AstNode | null {
  if (!node) { return null; }
  const targets = Array.isArray(types) ? types : [types];
  let found: AstNode | null = null;
  walkAst(node, (child) => {
    if (child !== node && targets.includes(child.type)) {
      found = child;
      return false;
    }
    return undefined;
  });
  return found;
}

function getDartCallArgumentsNode(node: AstNode): AstNode | null {
  if (node.type !== 'expression_statement' && node.type !== 'constructor_invocation') {
    return null;
  }
  return findFirstDescendantByType(node, 'arguments');
}

function getDartCallName(node: AstNode): string | null {
  if (node.type === 'constructor_invocation') {
    return namedChild(node, 0)?.text.replace(/\s+/g, '') ?? null;
  }
  if (node.type !== 'expression_statement' || !getDartCallArgumentsNode(node)) {
    return null;
  }

  const parts: string[] = [];
  for (const child of namedChildren(node)) {
    if (child.type === 'identifier') {
      parts.push(child.text);
      continue;
    }
    if (child.type !== 'selector') {
      continue;
    }
    if (findFirstDescendantByType(child, 'argument_part')) {
      break;
    }
    const identifier = findFirstDescendantByType(child, 'identifier');
    if (identifier) {
      parts.push(identifier.text);
    }
  }

  return parts.length > 0 ? parts.join('.') : null;
}
