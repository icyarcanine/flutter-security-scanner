import type { SyntaxNode } from 'web-tree-sitter';

type AstNode = SyntaxNode | any;

export function walkAst(node: AstNode, callback: (node: AstNode) => void | false) {
  if (callback(node) === false) {
    return;
  }
  for (let i = 0; i < namedChildCount(node); i++) {
    const child = namedChild(node, i);
    if (child) {
      walkAst(child, callback);
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
    'assignment',            // Python, Go
    'variable_declarator',   // JS, Java
    'short_var_declaration', // Go
    'augmented_assignment',   // Python
    'initialized_variable_definition', // Dart
  ].includes(node.type);
}

export function isFunctionCall(node: AstNode): boolean {
  if (node.type === 'expression_statement' && getDartCallArgumentsNode(node) != null) {
    return true;
  }

  return [
    'call_expression',     // JS, Python, Go
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

export function getAssignmentNames(node: AstNode, lang: string): string[] {
  // This extracts LHS of assignments to track what gets tainted
  const names: string[] = [];
  if (['assignment_expression', 'assignment'].includes(node.type)) {
    const left = childForFieldName(node, 'left');
    if (left?.text) names.push(left.text);
  } else if (node.type === 'variable_declarator') {
    const name = childForFieldName(node, 'name');
    if (name?.text) names.push(name.text);
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
    if (child.type === 'identifier') {
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
