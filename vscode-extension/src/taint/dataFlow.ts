import type { SyntaxNode } from 'web-tree-sitter';
import {
  childForFieldName,
  findNodesByType,
  getAssignmentNames,
  getAssignmentValue,
  getCallArguments,
  getCallName,
  getFunctionParameterGroups,
  getFunctionParameterNames,
  isAssignment,
  isAugmentedAssignment,
  isFunctionCall,
  namedChild,
  namedChildCount,
  walkAst,
} from '../ast/traversal';

export type SinkKind = 'sql' | 'command' | 'code' | 'html' | 'template' | 'url' | 'path' | 'redirect' | 'nosql';

/**
 * Confidence level of a taint chain.
 *   direct   — taint flows from a recognized source expression without
 *              passing through any opaque wrapper (symbol directly in tainted set,
 *              or a member access on a direct-source node).
 *   indirect — taint passes through an object literal, Object.assign mutation,
 *              computed property write, class-receiver (constructor→method), or
 *              an intra-file function summary.
 */
export type ChainStrength = 'direct' | 'indirect';

export interface TaintFinding {
  node: SyntaxNode;
  sinkName: string;
  sinkKind: SinkKind;
  isSanitized: boolean;
  chainStrength: ChainStrength;
}

export interface AstSinkFinding {
  node: SyntaxNode;
  sinkName: string;
  sinkKind: SinkKind;
  isSanitized: boolean;
}

interface SinkDefinition {
  name: string;
  kind: SinkKind;
}

/** Cached summary for same-file functions. */
interface FunctionSummary {
  /** True when the function body directly returns a known source expression. */
  returnsDirectSource: boolean;
}

interface ScopeState {
  /** Symbols that are directly tainted (strong: confirmed source access). */
  tainted: Set<string>;
  /**
   * Symbols that are indirectly tainted — passed through an object wrapper,
   * computed property write, Object.assign mutation, class receiver, etc.
   * Findings from weakTainted get chainStrength 'indirect' → MEDIUM confidence.
   */
  weakTainted: Set<string>;
  sanitized: Set<string>;
  dynamicSql: Set<string>;
  /** Alias depth for directly tainted symbols. Direct sources start at 0. */
  taintDepth: Map<string, number>;
  /** Literal properties present when an object/array was created. */
  literalProperties: Map<string, Set<string>>;
  /** Properties known to contain tainted values, e.g. `parts[0]`. */
  taintedProperties: Map<string, Set<string>>;
  /** Objects mutated from a tainted Object.assign source. */
  objectAssignTainted: Set<string>;
  /**
   * Names that are assigned inside a conditional block (if/else/switch/loop/try/ternary).
   * For these we refuse to trust sanitization because the sanitizing assignment
   * may not execute on every path. They can still be marked tainted, but never
   * promoted to sanitized.
   */
  conditionallyAssigned: Set<string>;
}

/** Maximum direct alias depth before taint downgrades to indirect. */
const MAX_TAINT_DEPTH = 3;

const SOURCE_PARAMETER_NAMES = new Set(['input', 'userInput', 'data', 'payload', 'req', 'request']);
/**
 * Field names commonly destructured from a request handler's first parameter.
 * When seen as bindings inside a destructuring pattern in a function parameter
 * slot, these are treated as tainted (they almost always come from `req`).
 */
const REQUEST_FIELD_NAMES = new Set([
  'query', 'body', 'params', 'headers', 'cookies', 'signedCookies',
  'session', 'files', 'rawHeaders', 'queryParams', 'pathParams',
]);
const FUNCTION_SCOPE_TYPES = [
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
];

const CLASS_NODE_TYPES = new Set(['class_declaration', 'class', 'class_definition']);

const CONDITIONAL_BLOCK_TYPES = new Set([
  // JavaScript/TypeScript
  'if_statement', 'else_clause', 'switch_statement', 'switch_case', 'switch_default',
  'while_statement', 'do_statement', 'for_statement', 'for_in_statement', 'for_of_statement',
  'ternary_expression', 'try_statement', 'catch_clause', 'finally_clause',
  // Python
  'if_clause', 'elif_clause', 'else_clause', 'for_in_clause', 'while_clause',
  'conditional_expression', 'try_clause', 'except_clause',
  // Dart
  'if_element', 'switch_case', 'switch_default', 'do_statement',
  // Go
  'if_statement', 'for_statement', 'switch_statement', 'type_switch_statement',
  'select_statement', 'case_clause', 'communication_case',
  // Java
  'enhanced_for_statement',
]);

/**
 * MongoDB collection methods that take a query/filter object as their first
 * argument. We don't treat these as sinks at the call level — that would
 * over-flag — but they're the entry points where `$where`-style operators
 * become dangerous.
 */
const NOSQL_COLLECTION_METHODS = new Set([
  'find', 'findone', 'findoneandupdate', 'findoneanddelete', 'findoneandreplace',
  'update', 'updateone', 'updatemany', 'replaceone',
  'delete', 'deleteone', 'deletemany',
  'count', 'countdocuments', 'estimateddocumentcount',
  'aggregate', 'distinct', 'findandmodify', 'remove',
]);

/**
 * MongoDB query operators that evaluate JavaScript on the server. Tainted
 * values flowing into any of these is direct code execution. Other operators
 * (e.g. `$eq`, `$gt`) are parameterized by the driver and tainted values
 * there are safe — so we deliberately do NOT include them here.
 */
const NOSQL_DANGEROUS_OPERATORS = new Set([
  '$where', '$function', '$accumulator',
]);

const SANITIZER_NAME_PATTERN =
  /(?:^|\.)(sanitize|escape|escapeHtml|escapeSql|escapeShell|shellEscape|sqlstring\.escape|dompurify\.sanitize|encodeURI|encodeURIComponent|encodeHTML|clean|normalize|validator\.escape)$/i;
const VALIDATION_NAME_PATTERN =
  /(?:^|\.)(validate|validated|assertValid|assertSafe|ensureValid|ensureSafe|checkValid|checkSafe|isAllowed|schema\.parse|safeParse|parseInt|parseFloat)$/i;

/**
 * Intra-procedural taint tracker for high-confidence source-to-sink findings.
 * It deliberately avoids inter-file and inter-procedural guesses to keep noise low.
 */
export class IntraProceduralTaintTracker {
  /** Populated by a pre-pass in findTaintedSinks; null between invocations. */
  private _summaries: Map<string, FunctionSummary> | null = null;

  public findTaintedSinks(root: SyntaxNode, lang: string): TaintFinding[] {
    const findings: TaintFinding[] = [];
    const scopes = this._scopes(root);
    // Final tainted state of each enclosing scope, used so nested closures
    // can inherit closure-captured variables. _scopes returns nodes in
    // pre-order, so a parent always appears before its children — by the
    // time we walk a child, its parent's final state is already recorded.
    // Keyed by node id (tree-sitter returns fresh node references on each
    // `.parent` access, so reference equality is unreliable).
    const finalStates = new Map<number, ScopeState>();

    // Pre-pass 1: compute intra-file function summaries (returnsDirectSource).
    this._summaries = this._computeFunctionSummaries(root);

    // Pre-pass 2: compute class receiver states so constructor-assigned
    // this.X props are injected as weakTainted into sibling method scopes.
    const classReceiverStates = this._computeClassReceiverStates(root);

    for (const scope of scopes) {
      const state = this._seedScope(scope);
      this._inheritFromEnclosing(scope, state, finalStates);
      this._injectClassReceiverTaint(scope, state, classReceiverStates);

      walkAst(scope, (node) => {
        if (node !== scope && FUNCTION_SCOPE_TYPES.includes(node.type)) {
          return false;
        }

        if (isFunctionCall(node)) {
          this._recordValidationCall(node, state);
          // Detect Object.assign(target, tainted) side-effect mutations.
          this._detectObjectAssignMutation(node, state);

          const sink = this._sinkForCall(node);
          if (sink) {
            const isSanitized = this._isSanitizedSinkCall(node, sink, state);
            const strength = this._callReceivesTaint(node, sink, state);
            if (strength !== false) {
              findings.push({ node, sinkName: sink.name, sinkKind: sink.kind, isSanitized, chainStrength: strength });
            }
          }

          // NoSQL injection: special-case detection because the danger lives
          // in a specific KEY of an object literal argument, not in the call
          // itself. This avoids treating every `find({ name: req.body.name })`
          // as a sink (those are parameterized by the driver).
          const nosqlFinding = this._checkNoSqlInjection(node, state);
          if (nosqlFinding) {
            findings.push(nosqlFinding);
          }
        }

        if (isAssignment(node)) {
          const assignmentSink = this._sinkForAssignment(node);
          if (assignmentSink) {
            const value = getAssignmentValue(node);
            const strength = value != null ? this._expressionTaintStrength(value, state) : false;
            if (strength !== false) {
              findings.push({
                node,
                sinkName: assignmentSink.name,
                sinkKind: assignmentSink.kind,
                isSanitized: this._isSanitizedExpression(value, state),
                chainStrength: strength,
              });
            }
          }

          this._propagateAssignment(node, lang, state);
        }
      });

      finalStates.set((scope as any).id, state);
    }

    this._summaries = null;
    return findings;
  }

  public findDynamicAstSinks(root: SyntaxNode, lang: string): AstSinkFinding[] {
    const findings: AstSinkFinding[] = [];
    const scopes = this._scopes(root);
    const finalStates = new Map<number, ScopeState>();

    for (const scope of scopes) {
      const state = this._seedScope(scope);
      this._inheritFromEnclosing(scope, state, finalStates);

      walkAst(scope, (node) => {
        if (node !== scope && FUNCTION_SCOPE_TYPES.includes(node.type)) {
          return false;
        }

        if (isFunctionCall(node)) {
          this._recordValidationCall(node, state);
          const sink = this._sinkForCall(node);
          if (sink && this._isDynamicSinkCall(node, sink, state)) {
            findings.push({
              node,
              sinkName: sink.name,
              sinkKind: sink.kind,
              isSanitized: this._isSanitizedSinkCall(node, sink, state),
            });
          }
        }

        if (isAssignment(node)) {
          const assignmentSink = this._sinkForAssignment(node);
          const value = getAssignmentValue(node);
          if (assignmentSink && value && this._isDynamicExpression(value, state)) {
            findings.push({
              node,
              sinkName: assignmentSink.name,
              sinkKind: assignmentSink.kind,
              isSanitized: this._isSanitizedExpression(value, state),
            });
          }

          this._propagateAssignment(node, lang, state);
        }
      });

      finalStates.set((scope as any).id, state);
    }
    return findings;
  }

  // ─── Pre-passes ───────────────────────────────────────────────────────────

  /**
   * Scans the root for named function declarations and records whether each
   * function's body directly returns a recognized source expression. Used
   * to give call-site taint credit when calling same-file getters like
   * `function getInput(req) { return req.body.id; }`.
   *
   * Scope: only same-file, only "return <direct-source>" bodies.
   * Passthrough (return param) is not tracked — the recursion in
   * _expressionTaintStrength already handles that.
   */
  private _computeFunctionSummaries(root: SyntaxNode): Map<string, FunctionSummary> {
    const summaries = new Map<string, FunctionSummary>();
    walkAst(root, (node) => {
      if (!FUNCTION_SCOPE_TYPES.includes(node.type)) { return; }
      const funcName = this._getFunctionName(node);
      if (!funcName) { return; }

      let returnsDirectSource = false;
      walkAst(node, (child) => {
        if (child !== node && FUNCTION_SCOPE_TYPES.includes(child.type)) { return false; }
        if (child.type !== 'return_statement') { return; }
        const returnVal = namedChild(child, 0);
        if (returnVal && this._isDirectSourceExpression(returnVal)) {
          returnsDirectSource = true;
        }
      });
      summaries.set(funcName, { returnsDirectSource });
    });
    return summaries;
  }

  private _getFunctionName(node: SyntaxNode): string | null {
    const nameNode = childForFieldName(node, 'name');
    return nameNode ? nameNode.text : null;
  }

  /**
   * Pre-pass: for each class in the file, seed the constructor's scope and
   * walk its body to discover which `this.X` properties become tainted.
   * Returns a map from class-node-id → Set<string> of tainted this.X props.
   * Non-constructor methods in the same class will have those props injected
   * into their `weakTainted` set via _injectClassReceiverTaint.
   */
  private _computeClassReceiverStates(root: SyntaxNode): Map<number, Set<string>> {
    const classReceiverStates = new Map<number, Set<string>>();

    walkAst(root, (node) => {
      if (!CLASS_NODE_TYPES.has(node.type)) { return; }

      const classId = (node as any).id;
      const taintedThisProps = new Set<string>();

      walkAst(node, (child) => {
        if (child !== node && CLASS_NODE_TYPES.has(child.type)) { return false; } // nested class
        if (!this._isConstructorMethod(child)) { return; }

        const ctorState = this._seedScope(child);
        walkAst(child, (ctorNode) => {
          if (ctorNode !== child && FUNCTION_SCOPE_TYPES.includes(ctorNode.type)) { return false; }
          if (isAssignment(ctorNode)) {
            const value = getAssignmentValue(ctorNode);
            if (value && this._isExpressionTainted(value, ctorState)) {
              const targets = getAssignmentNames(ctorNode, '');
              for (const target of targets) {
                const sym = this._normalizeSymbol(target);
                if (sym && sym.startsWith('this.')) {
                  taintedThisProps.add(sym);
                }
              }
            }
            this._propagateAssignment(ctorNode, '', ctorState);
          }
        });
        return false; // only process the first constructor found
      });

      if (taintedThisProps.size > 0) {
        classReceiverStates.set(classId, taintedThisProps);
      }
    });

    return classReceiverStates;
  }

  private _isConstructorMethod(node: SyntaxNode): boolean {
    if (!FUNCTION_SCOPE_TYPES.includes(node.type)) { return false; }
    const nameNode = childForFieldName(node, 'name');
    if (nameNode?.text === 'constructor') { return true; }
    // Python __init__
    if (node.type === 'function_definition' && nameNode?.text === '__init__') { return true; }
    return false;
  }

  /**
   * Injects tainted this.X props from the class constructor into the given
   * scope's weakTainted set, enabling constructor→method taint propagation.
   * Uses weakTainted (indirect) because cross-method flow is not confirmed
   * within a single call site.
   */
  private _injectClassReceiverTaint(
    scope: SyntaxNode,
    state: ScopeState,
    classReceiverStates: Map<number, Set<string>>,
  ): void {
    if (this._isConstructorMethod(scope)) { return; } // don't inject into the constructor itself

    let parent: SyntaxNode | null = scope.parent;
    while (parent) {
      if (CLASS_NODE_TYPES.has(parent.type)) {
        const classId = (parent as any).id;
        const receiverProps = classReceiverStates.get(classId);
        if (receiverProps) {
          for (const prop of receiverProps) {
            state.tainted.add(prop);
            state.weakTainted.delete(prop);
            state.taintDepth.set(prop, 0);
          }
        }
        return;
      }
      parent = parent.parent;
    }
  }

  /**
   * Detects `Object.assign(target, tainted_source)` calls and marks the
   * target symbol as weakTainted. We skip fresh object literals (`{}`) as
   * the target because those are used as the *return value* pattern
   * (`Object.assign({}, src)`) — the assignment itself handles that via
   * normal _propagateAssignment → _expressionTaintStrength recursion.
   */
  private _detectObjectAssignMutation(node: SyntaxNode, state: ScopeState): void {
    const name = getCallName(node);
    if (name.toLowerCase() !== 'object.assign') { return; }

    const args = getCallArguments(node);
    if (args.length < 2) { return; }

    const anySourceTainted = args.slice(1).some(arg => this._expressionTaintStrength(arg, state) !== false);
    if (!anySourceTainted) { return; }

    const target = args[0];
    if (!target) { return; }
    // Skip fresh {} literals — their taint is handled by the return-value assignment.
    if (target.type === 'object' || target.type === 'object_expression') { return; }

    const sym = this._normalizeSymbol(target.text);
    if (sym) {
      state.objectAssignTainted.add(sym);
      state.weakTainted.add(sym);
      if (!state.taintDepth.has(sym)) {
        state.taintDepth.set(sym, MAX_TAINT_DEPTH);
      }
    }
  }

  // ─── Scope management ─────────────────────────────────────────────────────

  /**
   * Closure capture: copy the enclosing function's final tainted/sanitized
   * state into this nested scope so that an inner arrow can see variables
   * defined in its outer scope. Without this, an outer scope assigning
   * `id = req.body.id` would not propagate `id` into a nested handler that
   * uses it. We copy by value so that mutations in the nested scope don't
   * leak back into the parent — that approximation matches what an
   * intra-procedural model can guarantee.
   */
  private _inheritFromEnclosing(
    scope: SyntaxNode,
    state: ScopeState,
    finalStates: Map<number, ScopeState>,
  ): void {
    let parent: SyntaxNode | null = scope.parent;
    while (parent) {
      if (FUNCTION_SCOPE_TYPES.includes(parent.type)) {
        const parentState = finalStates.get((parent as any).id);
        if (parentState) {
          for (const t of parentState.tainted) { state.tainted.add(t); }
          for (const t of parentState.weakTainted) { state.weakTainted.add(t); }
          for (const s of parentState.sanitized) { state.sanitized.add(s); }
          for (const d of parentState.dynamicSql) { state.dynamicSql.add(d); }
          for (const [sym, depth] of parentState.taintDepth) { state.taintDepth.set(sym, depth); }
          this._mergePropertyMap(state.literalProperties, parentState.literalProperties);
          this._mergePropertyMap(state.taintedProperties, parentState.taintedProperties);
          for (const sym of parentState.objectAssignTainted) { state.objectAssignTainted.add(sym); }
        }
        return;
      }
      parent = parent.parent;
    }
  }

  private _scopes(root: SyntaxNode): SyntaxNode[] {
    const scopes = findNodesByType(root, FUNCTION_SCOPE_TYPES);
    return scopes.length > 0 ? scopes : [root];
  }

  private _seedScope(scope: SyntaxNode): ScopeState {
    const tainted = new Set<string>();
    const taintDepth = new Map<string, number>();

    // Direct identifier params: req, request, input, userInput, data, payload
    for (const name of getFunctionParameterNames(scope)) {
      if (SOURCE_PARAMETER_NAMES.has(name)) {
        tainted.add(name);
        taintDepth.set(name, 0);
      }
    }

    // Destructured params: ({ query, body }, res) => ...
    // If a destructuring slot exposes a well-known request field name,
    // treat it as tainted (the binding name carries the value of req.<name>).
    // We rely on the explicit `destructured` flag from getFunctionParameterGroups
    // because a single destructured slot like `({ query })` is structurally
    // different from a bare `function f(query)` even though both expose one
    // name — only the former is implicitly bound to a request object.
    const slots = getFunctionParameterGroups(scope);
    for (const slot of slots) {
      if (!slot.destructured) { continue; }
      for (const name of slot.names) {
        if (REQUEST_FIELD_NAMES.has(name)) {
          tainted.add(name);
          taintDepth.set(name, 0);
        }
      }
    }

    const conditionallyAssigned = this._collectConditionallyAssigned(scope);
    return {
      tainted,
      weakTainted: new Set<string>(),
      sanitized: new Set<string>(),
      dynamicSql: new Set<string>(),
      taintDepth,
      literalProperties: new Map<string, Set<string>>(),
      taintedProperties: new Map<string, Set<string>>(),
      objectAssignTainted: new Set<string>(),
      conditionallyAssigned,
    };
  }

  private _mergePropertyMap(target: Map<string, Set<string>>, source: Map<string, Set<string>>): void {
    for (const [objectName, props] of source) {
      const merged = target.get(objectName) ?? new Set<string>();
      for (const prop of props) { merged.add(prop); }
      target.set(objectName, merged);
    }
  }

  /**
   * Pre-pass: walks the scope to find all variables assigned inside any
   * conditional block. Used to gate sanitization promotion — a variable
   * sanitized only inside an if-branch should not be treated as fully sanitized.
   */
  private _collectConditionallyAssigned(scope: SyntaxNode): Set<string> {
    const result = new Set<string>();
    walkAst(scope, (node) => {
      if (node !== scope && FUNCTION_SCOPE_TYPES.includes(node.type)) {
        return false; // do not descend into nested functions
      }
      if (!isAssignment(node)) { return; }
      if (!this._isInsideConditionalBlock(node, scope)) { return; }

      const names = getAssignmentNames(node, '');
      for (const raw of names) {
        const sym = this._normalizeSymbol(raw);
        if (sym) { result.add(sym); }
      }
    });
    return result;
  }

  private _isInsideConditionalBlock(node: SyntaxNode, scope: SyntaxNode): boolean {
    let current: SyntaxNode | null = node.parent;
    while (current && current !== scope) {
      if (CONDITIONAL_BLOCK_TYPES.has(current.type)) { return true; }
      current = current.parent;
    }
    return false;
  }

  private _propagateAssignment(node: SyntaxNode, lang: string, state: ScopeState): void {
    const targets = getAssignmentNames(node, lang)
      .map(name => this._normalizeSymbol(name))
      .filter((name): name is string => name != null);
    if (targets.length === 0) { return; }

    const value = getAssignmentValue(node);
    const isSanitized = this._isSanitizedExpression(value, state);
    const strength = value != null ? this._expressionTaintStrength(value, state) : false;
    const isDynamicSql = value != null && this._isDynamicSqlExpressionWithState(value, state);
    const augmented = isAugmentedAssignment(node);
    const literalProperties = value ? this._literalPropertyNames(value) : null;
    const taintedProperties = value ? this._literalTaintedPropertyNames(value, state) : new Set<string>();

    for (const target of targets) {
      const isConditional = state.conditionallyAssigned.has(target);

      if (!augmented) {
        if (literalProperties) {
          state.literalProperties.set(target, literalProperties);
        } else {
          state.literalProperties.delete(target);
          state.objectAssignTainted.delete(target);
        }

        if (taintedProperties.size > 0) {
          state.taintedProperties.set(target, taintedProperties);
        } else {
          state.taintedProperties.delete(target);
        }
      }

      if (strength !== false && !isSanitized) {
        if (strength === 'direct') {
          const newDepth = this._getExpressionDepth(value!, state) + 1;
          if (newDepth > MAX_TAINT_DEPTH) {
            state.weakTainted.add(target);
            state.tainted.delete(target);
            state.taintDepth.delete(target);
          } else {
            state.tainted.add(target);
            state.weakTainted.delete(target);
            state.taintDepth.set(target, newDepth);
          }
        } else {
          // 'indirect': add to weakTainted; never demote an existing direct taint.
          state.weakTainted.add(target);
          if (!state.taintDepth.has(target)) {
            state.taintDepth.set(target, MAX_TAINT_DEPTH);
          }
          // Leave state.tainted alone — if target was already directly tainted, keep it.
        }
        state.sanitized.delete(target);
      } else if (isSanitized) {
        if (isConditional || augmented) {
          // Conditional sanitization: refuse to mark as sanitized because the
          // sanitizing branch may not execute on every path. Preserve any
          // existing tainted state from a prior assignment so the sink check
          // still fires.
          // Augmented assignment (`x += sanitized`) also can't clear earlier
          // taint — the LHS is concatenated with, not replaced by, the RHS.
        } else {
          state.tainted.delete(target);
          state.weakTainted.delete(target);
          state.taintDepth.delete(target);
          state.taintedProperties.delete(target);
          state.objectAssignTainted.delete(target);
          state.sanitized.add(target);
        }
      } else {
        // Unknown value (e.g. another function call). Conditional rebinding
        // shouldn't clear an earlier tainted marking — only unconditional
        // overwrites should reset state. Augmented assignment also preserves
        // existing taint.
        if (!isConditional && !augmented) {
          state.tainted.delete(target);
          state.weakTainted.delete(target);
          state.taintDepth.delete(target);
          state.taintedProperties.delete(target);
          state.objectAssignTainted.delete(target);
          state.sanitized.delete(target);
        }
      }

      if (isDynamicSql && !isSanitized) {
        state.dynamicSql.add(target);
      } else if (!isConditional && !augmented) {
        state.dynamicSql.delete(target);
      }
    }
  }

  private _literalPropertyNames(node: SyntaxNode): Set<string> | null {
    if (node.type === 'array' || node.type === 'array_expression') {
      const props = new Set<string>();
      for (let i = 0; i < namedChildCount(node); i++) {
        props.add(String(i));
      }
      return props;
    }

    if (!(node.type === 'object' || node.type === 'object_expression' || node.type === 'dictionary')) {
      return null;
    }

    const props = new Set<string>();
    walkAst(node, (child) => {
      if (child !== node && (child.type === 'object' || child.type === 'object_expression' ||
          child.type === 'dictionary' || child.type === 'array' || child.type === 'array_expression')) {
        return false;
      }
      if (child.type !== 'pair') { return; }
      const prop = this._propertyNameFromKey(childForFieldName(child, 'key'));
      if (prop) { props.add(prop); }
    });
    return props;
  }

  private _literalTaintedPropertyNames(node: SyntaxNode, state: ScopeState): Set<string> {
    const props = new Set<string>();

    if (node.type === 'array' || node.type === 'array_expression') {
      for (let i = 0; i < namedChildCount(node); i++) {
        const child = namedChild(node, i);
        if (child && this._expressionTaintStrength(child, state) !== false) {
          props.add(String(i));
        }
      }
      return props;
    }

    if (!(node.type === 'object' || node.type === 'object_expression' || node.type === 'dictionary')) {
      return props;
    }

    walkAst(node, (child) => {
      if (child !== node && (child.type === 'object' || child.type === 'object_expression' ||
          child.type === 'dictionary' || child.type === 'array' || child.type === 'array_expression')) {
        return false;
      }
      if (child.type !== 'pair') { return; }
      const prop = this._propertyNameFromKey(childForFieldName(child, 'key'));
      const value = childForFieldName(child, 'value');
      if (prop && value && this._expressionTaintStrength(value, state) !== false) {
        props.add(prop);
      }
    });
    return props;
  }

  private _propertyNameFromKey(node: SyntaxNode | null): string | null {
    if (!node) { return null; }
    return node.text.replace(/^["'`]|["'`]$/g, '');
  }

  private _getExpressionDepth(node: SyntaxNode, state: ScopeState): number {
    if (this._isDirectSourceExpression(node)) { return 0; }
    const symbol = this._normalizeSymbol(node.text);
    if (symbol) {
      if (state.taintDepth.has(symbol)) { return state.taintDepth.get(symbol)!; }
      if (state.weakTainted.has(symbol)) { return MAX_TAINT_DEPTH; }
    }

    let maxDepth = 0;
    for (let i = 0; i < namedChildCount(node); i++) {
      const child = namedChild(node, i);
      if (!child || this._expressionTaintStrength(child, state) === false) { continue; }
      const depth = this._getExpressionDepth(child, state);
      if (depth > maxDepth) { maxDepth = depth; }
    }
    return maxDepth;
  }

  private _recordValidationCall(node: SyntaxNode, state: ScopeState): void {
    const name = getCallName(node);
    if (!VALIDATION_NAME_PATTERN.test(name)) { return; }

    for (const arg of getCallArguments(node)) {
      if (!this._isExpressionTainted(arg, state)) { continue; }
      this._markSanitized(arg, state);
    }
  }

  // ─── Taint strength model ─────────────────────────────────────────────────

  /**
   * Core confidence method: returns the taint strength of a given expression,
   * or false if the expression is not tainted.
   *
   * 'direct'   — confirmed source access: symbol in tainted set, direct source
   *              expression (req.body.x), or intra-file function returning a
   *              direct source.
   * 'indirect' — taint passes through a wrapper: symbol in weakTainted,
   *              base object has a tainted property, object/array literal
   *              containing tainted values.
   * false      — not tainted (or sanitized).
   *
   * Weak taint is exact for member access: `obj` in weakTainted does not make
   * `obj.id` tainted unless `obj.id` or one of its properties was tracked.
   */
  private _expressionTaintStrength(node: SyntaxNode | null, state: ScopeState): ChainStrength | false {
    if (!node) { return false; }

    const symbol = this._normalizeSymbol(node.text);

    // Sanitized symbols are never tainted.
    if (symbol && state.sanitized.has(symbol)) { return false; }

    // Direct symbol taint — strongest signal.
    if (symbol && state.tainted.has(symbol)) { return 'direct'; }

    // Indirect symbol taint.
    if (symbol && state.weakTainted.has(symbol)) { return 'indirect'; }

    // Recognized direct source expressions (req.body.x, request.args.get(), etc.)
    if (this._isDirectSourceExpression(node)) { return 'direct'; }

    if (symbol) {
      const propertyStrength = this._memberPropertyTaintStrength(symbol, state);
      if (propertyStrength) { return propertyStrength; }
    }

    // Symbol is a base object with tainted properties (e.g. `cfg` when `cfg.id` is tainted).
    if (symbol && this._isObjectTainted(symbol, state)) { return 'indirect'; }

    // Sanitizer/validator call — trusted output regardless of args.
    if (this._isSanitizedExpression(node, state)) { return false; }

    // Object/array literals: tainted children downgrade strength by one level
    // because the object wraps the taint rather than being the direct source.
    if (node.type === 'object' || node.type === 'object_expression' ||
        node.type === 'dictionary' || node.type === 'array' || node.type === 'array_expression') {
      for (let i = 0; i < namedChildCount(node); i++) {
        const child = namedChild(node, i);
        if (child && this._expressionTaintStrength(child, state) !== false) {
          return 'indirect';
        }
      }
      return false;
    }

    // Intra-file function summaries: a function that directly returns a source
    // expression contributes direct taint at its call site.
    if (isFunctionCall(node) && this._summaries) {
      const callName = getCallName(node);
      const summary = this._summaries.get(callName);
      if (summary?.returnsDirectSource) { return 'direct'; }
      // Fall through to child recursion — tainted args still propagate
      // through unknown (non-summarized, non-sanitizer) calls.
    }

    // Recursive child scan — find the strongest taint signal in sub-expressions.
    const memberAccess = this._isMemberAccessExpression(node);
    let result: ChainStrength | false = false;
    for (let i = 0; i < namedChildCount(node); i++) {
      const child = namedChild(node, i);
      if (!child) { continue; }
      const childStrength = this._expressionTaintStrength(child, state);
      if (childStrength === 'direct') { return 'direct'; }
      if (childStrength === 'indirect' && !memberAccess) { result = 'indirect'; }
    }
    return result;
  }

  private _isMemberAccessExpression(node: SyntaxNode): boolean {
    return [
      'member_expression',
      'member_access_expression',
      'field_expression',
      'selector_expression',
      'subscript_expression',
      'element_access_expression',
      'index_expression',
      'attribute',
      'attribute_expression',
    ].includes(node.type);
  }

  private _memberPropertyTaintStrength(symbol: string, state: ScopeState): ChainStrength | false {
    const member = this._splitMemberSymbol(symbol);
    if (!member) { return false; }

    const taintedProps = state.taintedProperties.get(member.base);
    if (taintedProps?.has(member.property)) { return 'direct'; }

    if (state.objectAssignTainted.has(member.base)) {
      const literalProps = state.literalProperties.get(member.base);
      if (!literalProps?.has(member.property)) {
        return 'direct';
      }
    }

    return false;
  }

  private _splitMemberSymbol(symbol: string): { base: string; property: string } | null {
    const dot = symbol.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\.([A-Za-z_$][A-Za-z0-9_$]*)/);
    if (dot) {
      return { base: dot[1], property: dot[2] };
    }

    const bracket = symbol.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\[(?:"([^"]+)"|'([^']+)'|([^\]]+))\]/);
    if (bracket) {
      return { base: bracket[1], property: bracket[2] ?? bracket[3] ?? bracket[4] };
    }

    return null;
  }

  /**
   * Returns true if any property of `sym` (i.e. `sym.X` or `sym[X]`) is in
   * the tainted or weakTainted set. Used to detect when a base object symbol
   * is tainted due to computed property writes or specific prop assignments.
   */
  private _isObjectTainted(sym: string, state: ScopeState): boolean {
    const prefix1 = sym + '.';
    const prefix2 = sym + '[';
    for (const t of state.tainted) {
      if (t.startsWith(prefix1) || t.startsWith(prefix2)) { return true; }
    }
    for (const t of state.weakTainted) {
      if (t.startsWith(prefix1) || t.startsWith(prefix2)) { return true; }
    }
    return false;
  }

  /** Boolean wrapper around _expressionTaintStrength for compatibility. */
  private _isExpressionTainted(node: SyntaxNode | null, state: ScopeState): boolean {
    return this._expressionTaintStrength(node, state) !== false;
  }

  private _callReceivesTaint(node: SyntaxNode, sink: SinkDefinition, state: ScopeState): ChainStrength | false {
    const args = getCallArguments(node);
    if (args.length === 0) { return false; }

    if (sink.kind === 'sql') {
      const first = args[0];
      const firstStrength = first != null ? this._expressionTaintStrength(first, state) : false;
      if (firstStrength) { return firstStrength; }
      // Also check other args unless the call is parameterized.
      if (!this._isParameterizedSqlCall(node, sink, state)) {
        let best: ChainStrength | false = false;
        for (const arg of args) {
          const s = this._expressionTaintStrength(arg, state);
          if (s === 'direct') { return 'direct'; }
          if (s === 'indirect') { best = 'indirect'; }
        }
        return best;
      }
      return false;
    }

    // For non-SQL sinks, the dangerous slot is almost always the FIRST argument
    // (the path/url/content/code/template). Checking every argument flagged
    // legitimate calls like `fs.writeFileSync(path, content)` whenever the
    // CONTENT contained anything tainted-looking — even though the danger of a
    // path sink is the path itself, not the data being written. Restricting to
    // the relevant argument(s) eliminates that class of FP without missing
    // anything: the actual sink semantic always lives in the first slot.
    switch (sink.kind) {
      case 'path':
      case 'url':
      case 'redirect':
      case 'template':
        return args[0] != null ? this._expressionTaintStrength(args[0], state) : false;
      case 'code': {
        // Code sinks (eval, Function, setTimeout, setInterval) are dangerous
        // when the first arg is a STRING that the engine evaluates. If the
        // arg is a function expression / arrow function, the sink is benign
        // (`setTimeout(() => doThing(), 1000)`). Filter those out before
        // checking taint.
        const first = args[0];
        if (!first) { return false; }
        if (first.type === 'arrow_function' || first.type === 'function' ||
            first.type === 'function_expression' || first.type === 'function_declaration' ||
            first.type === 'lambda' || first.type === 'lambda_expression') {
          return false;
        }
        return this._expressionTaintStrength(first, state);
      }
      case 'html':
        // innerHTML/document.write — first arg is the markup.
        return args[0] != null ? this._expressionTaintStrength(args[0], state) : false;
      case 'command': {
        // child_process.spawn(file, args[, opts]) — both `file` and `args`
        // can carry attacker-controlled data into the shell, so check those
        // two slots only. The third arg (options) is config and shouldn't
        // gate the finding.
        const s0 = this._expressionTaintStrength(args[0], state);
        if (s0 === 'direct') { return 'direct'; }
        const s1 = args[1] != null ? this._expressionTaintStrength(args[1], state) : false;
        if (s1 === 'direct') { return 'direct'; }
        if (s0 === 'indirect' || s1 === 'indirect') { return 'indirect'; }
        return false;
      }
    }

    // Fallback: check all args, return the strongest signal.
    let best: ChainStrength | false = false;
    for (const arg of args) {
      const s = this._expressionTaintStrength(arg, state);
      if (s === 'direct') { return 'direct'; }
      if (s === 'indirect') { best = 'indirect'; }
    }
    return best;
  }

  private _isSanitizedExpression(node: SyntaxNode | null, state: ScopeState): boolean {
    if (!node) { return false; }
    const symbol = this._normalizeSymbol(node.text);
    if (symbol && state.sanitized.has(symbol)) { return true; }

    if (isFunctionCall(node)) {
      const name = getCallName(node);
      if (SANITIZER_NAME_PATTERN.test(name) || VALIDATION_NAME_PATTERN.test(name)) {
        return true;
      }
    }

    return false;
  }

  private _isDirectSourceExpression(node: SyntaxNode): boolean {
    // Strip whitespace and treat optional-chaining (`?.`) the same as a
    // plain dot — `req?.query?.id` should be tracked just like `req.query.id`.
    // Also normalize bracket-notation (`req['body']['x']`) to dot-notation so
    // both styles fall through the same regexes.
    let compact = node.text.replace(/\s+/g, '').replace(/\?\./g, '.');
    compact = compact.replace(/\[(?:'([^']+)'|"([^"]+)")\]/g, (_m, a, b) => '.' + (a ?? b));
    if (/^(?:req|request)\.(?:body|query|params|file|files)(?:\.|\[|$)/.test(compact)) {
      return true;
    }
    if (/^(?:req|request)\.(?:uri\.queryparameters|queryparameters|headers|cookies|signedCookies|session|rawHeaders)(?:\.|\[|$)/i.test(compact)) {
      return true;
    }
    if (/^(?:stdin|io\.stdin)\.readlinesync\(/i.test(compact)) {
      return true;
    }
    if (/^platform\.environment(?:\.|\[|$)/i.test(compact)) {
      return true;
    }
    if (/(?:^|\.)(?:text|value)$/.test(compact) && /controller|field|input/i.test(compact)) {
      return true;
    }
    if (/^process\.env(?:\.|\[|$)/.test(compact)) {
      return true;
    }
    if (/^(?:process\.)?stdin(?:\.|\[|$)/i.test(compact)) {
      return true;
    }
    // Flask / Django sources
    if (/^request\.(?:args|form|values|json|cookies|headers|files|data)(?:\.|\[|$)/.test(compact)) {
      return true;
    }
    if (/^request\.(?:args|form|values|json|cookies|headers)\.get\(/.test(compact)) {
      return true;
    }
    // FastAPI / Starlette
    if (/^request\.(?:query_params|path_params)(?:\.|\[|$)/.test(compact)) {
      return true;
    }
    return false;
  }

  private _markSanitized(node: SyntaxNode, state: ScopeState): void {
    const symbols = new Set<string>();
    const exact = this._normalizeSymbol(node.text);
    if (exact) { symbols.add(exact); }

    for (let i = 0; i < namedChildCount(node); i++) {
      const child = namedChild(node, i);
      if (!child) { continue; }
      const childSymbol = this._normalizeSymbol(child.text);
      if (childSymbol) { symbols.add(childSymbol); }
    }

    for (const symbol of symbols) {
      state.tainted.delete(symbol);
      state.weakTainted.delete(symbol);
      state.taintDepth.delete(symbol);
      state.sanitized.add(symbol);
    }
  }

  // ─── Sink detection ───────────────────────────────────────────────────────

  private _sinkForCall(node: SyntaxNode): SinkDefinition | null {
    const fullName = getCallName(node);
    const bareName = fullName.split('.').pop() ?? fullName;
    const lowerFull = fullName.toLowerCase();
    const lowerBare = bareName.toLowerCase();

    if (['query', 'execute', 'executequery', 'raw', 'rawquery', 'executemany', 'executescript'].includes(lowerBare)) {
      return { name: fullName, kind: 'sql' };
    }

    if (['exec', 'execsync', 'execfile', 'spawn', 'system', 'popen'].includes(lowerBare) ||
      lowerFull === 'os.system' ||
      lowerFull === 'os.popen' ||
      lowerFull === 'subprocess.run' ||
      lowerFull === 'subprocess.call' ||
      lowerFull === 'subprocess.check_output' ||
      lowerFull === 'subprocess.popen' ||
      lowerFull === 'process.run' ||
      lowerFull === 'process.start') {
      return { name: fullName, kind: 'command' };
    }

    if (fullName === 'eval' || fullName === 'Function' || lowerBare === 'eval' ||
      lowerBare === 'compile' && lowerFull === 'compile') {
      return { name: fullName, kind: 'code' };
    }

    if (lowerFull === 'document.write' || lowerBare === 'innerhtml') {
      return { name: fullName, kind: 'html' };
    }

    // SSRF — outbound HTTP / network sinks. Tainted URLs reaching these can
    // cause server-side request forgery, allowing attackers to probe internal
    // services. We only flag full taint flow (HIGH) — dynamic URLs alone are
    // too noisy because legitimate proxies/clients pass URLs all the time.
    if (lowerBare === 'fetch' && fullName === 'fetch') {
      return { name: fullName, kind: 'url' };
    }
    if (/^axios(?:\.(?:get|post|put|delete|patch|head|options|request))?$/i.test(fullName)) {
      return { name: fullName, kind: 'url' };
    }
    if (/^https?\.(?:get|request)$/i.test(fullName)) {
      return { name: fullName, kind: 'url' };
    }
    if (/^requests\.(?:get|post|put|delete|patch|head|options|request)$/i.test(fullName)) {
      return { name: fullName, kind: 'url' };
    }
    if (lowerFull === 'urllib.request.urlopen' || lowerBare === 'urlopen') {
      return { name: fullName, kind: 'url' };
    }

    // Path traversal — file system reads/writes with attacker-controlled
    // paths. Restricted to fs.<method> shapes to avoid flagging unrelated
    // helpers named `readFile` on application objects.
    if (/^fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|appendFile|appendFileSync|open|openSync|unlink|unlinkSync|stat|statSync|lstat|lstatSync|readdir|readdirSync)$/.test(fullName)) {
      return { name: fullName, kind: 'path' };
    }

    // Open redirect — flagging tainted URLs flowing into res.redirect /
    // res.location. Common in Express handlers.
    if (/^res\.(?:redirect|location)$/.test(fullName)) {
      return { name: fullName, kind: 'redirect' };
    }

    // Code execution via setTimeout/setInterval string argument. Strings
    // passed to these are eval'd; this is one of the classic JS gotchas.
    if (lowerBare === 'settimeout' || lowerBare === 'setinterval') {
      return { name: fullName, kind: 'code' };
    }

    // Server-side template / SSTI sinks
    if (lowerBare === 'render_template_string' || lowerFull === 'flask.render_template_string' ||
      lowerBare === 'render_string' ||
      lowerBare === 'from_string' && /jinja|env|environment/i.test(fullName) ||
      lowerBare === 'template' && /jinja/i.test(fullName)) {
      return { name: fullName, kind: 'template' };
    }

    // Insecure deserialization. These functions execute attacker-controlled
    // serialized data as code, so any tainted input is direct RCE. We
    // restrict to specific function names to keep FP near zero — pickle.loads
    // / yaml.load / marshal.loads are essentially never benign on user input.
    if (lowerFull === 'pickle.loads' || lowerFull === 'pickle.load' ||
        lowerFull === 'cpickle.loads' || lowerFull === 'cpickle.load' ||
        lowerFull === '_pickle.loads' || lowerFull === '_pickle.load' ||
        lowerFull === 'marshal.loads' || lowerFull === 'marshal.load' ||
        lowerFull === 'shelve.open' ||
        lowerFull === 'yaml.load' || lowerFull === 'yaml.load_all' ||
        lowerFull === 'yaml.unsafe_load' || lowerFull === 'yaml.full_load') {
      return { name: fullName, kind: 'code' };
    }

    // XPath injection — selectSingleNode / xpath.select with concatenated
    // user input. The sink is unambiguous; we only fire on confirmed taint.
    if (lowerBare === 'selectsinglenode' || lowerBare === 'selectnodes' ||
        lowerFull === 'xpath.select' || lowerFull === 'xpath.select1' ||
        lowerFull === 'xpath.evaluate' || lowerBare === 'evaluate' && /xpath/i.test(fullName)) {
      return { name: fullName, kind: 'sql' };
    }

    // LDAP injection — ldap.search with attacker-controlled filter strings.
    if (/^ldap(?:client)?\.search$/i.test(fullName) ||
        /\.search_s$/i.test(fullName) ||
        /^ldap\.searchEntries?$/i.test(fullName)) {
      return { name: fullName, kind: 'sql' };
    }

    return null;
  }

  private _sinkForAssignment(node: SyntaxNode): SinkDefinition | null {
    const left = childForFieldName(node, 'left') ?? childForFieldName(node, 'name') ?? namedChild(node, 0);
    const compact = left?.text.replace(/\s+/g, '') ?? '';
    if (/(?:^|\.)(innerHTML|outerHTML)$/.test(compact)) {
      return { name: compact, kind: 'html' };
    }
    return null;
  }

  private _isSanitizedSinkCall(node: SyntaxNode, sink: SinkDefinition, state: ScopeState): boolean {
    if (sink.kind === 'sql' && this._isParameterizedSqlCall(node, sink, state)) {
      return true;
    }

    return getCallArguments(node).some(arg => this._isSanitizedExpression(arg, state));
  }

  private _isParameterizedSqlCall(node: SyntaxNode, sink: SinkDefinition, state: ScopeState): boolean {
    if (sink.kind !== 'sql') { return false; }
    const args = getCallArguments(node);
    if (args.length < 2) { return false; }

    const sqlArg = args[0];
    if (!sqlArg || this._isExpressionTainted(sqlArg, state) || this._isDynamicSqlExpressionWithState(sqlArg, state)) {
      return false;
    }

    const parametersArg = args[1];
    if (!parametersArg) { return false; }
    const parameterText = parametersArg.text.trim();
    return parameterText.startsWith('[') ||
      parameterText.startsWith('{') ||
      parameterText.startsWith('(') ||
      /params|values|bindings|parameters/i.test(parameterText);
  }

  private _isDynamicSinkCall(node: SyntaxNode, sink: SinkDefinition, state: ScopeState): boolean {
    const args = getCallArguments(node);
    if (args.length === 0) { return false; }
    if (this._isSanitizedSinkCall(node, sink, state)) { return false; }

    switch (sink.kind) {
      case 'sql':
        return this._isDynamicSqlExpressionWithState(args[0], state) &&
          this._hasUntrustedDynamicParts(args[0], state);
      case 'command':
        return this._isDynamicExpression(args[0], state) &&
          this._hasUntrustedDynamicParts(args[0], state);
      case 'code':
        return this._hasUntrustedDynamicParts(args[0], state);
      case 'html':
        return args.some(arg =>
          this._isDynamicExpression(arg, state) && this._hasUntrustedDynamicParts(arg, state));
      case 'template':
        // Server-side template injection: ANY dynamic content in the template
        // string is dangerous, since the engine will evaluate it.
        return this._isDynamicExpression(args[0], state) &&
          this._hasUntrustedDynamicParts(args[0], state);
      case 'url':
        // Don't emit dynamic-only SSRF findings — too noisy. We only want
        // confirmed taint flow (which goes through findTaintedSinks instead).
        return false;
      case 'path':
        // Same reasoning as 'url' — file path arguments are routinely dynamic
        // and benign (e.g., reading config from a computed path). Confirmed
        // taint flow is the only meaningful signal.
        return false;
      case 'redirect':
        // Open redirect dynamic-only is also too noisy.
        return false;
      case 'nosql':
        // Detected only via _checkNoSqlInjection structural check.
        return false;
    }
  }

  /**
   * NoSQL injection detector: looks for MongoDB-style collection methods
   * (find/findOne/update/delete/aggregate) called with an object literal
   * whose `$where`, `$function`, or `$accumulator` key is bound to a
   * tainted value. These three operators evaluate JavaScript on the server,
   * so user-controlled values flowing in are direct code execution.
   *
   * Other keys (`name`, `id`, etc.) are intentionally NOT checked: those
   * are parameterized by the driver and tainted values there are safe.
   * Restricting to the JS-evaluating operators keeps FP risk near zero.
   */
  private _checkNoSqlInjection(node: SyntaxNode, state: ScopeState): TaintFinding | null {
    const fullName = getCallName(node);
    const bareName = fullName.split('.').pop() ?? fullName;
    if (!NOSQL_COLLECTION_METHODS.has(bareName.toLowerCase())) {
      return null;
    }

    const args = getCallArguments(node);
    if (args.length === 0) { return null; }

    for (const arg of args) {
      if (!arg) { continue; }
      // Walk for pair nodes whose key is one of the dangerous JS-eval operators
      let found: SyntaxNode | null = null;
      let foundStrength: ChainStrength = 'direct';
      walkAst(arg, (child) => {
        if (found) { return false; }
        if (child.type !== 'pair') { return; }
        const key = childForFieldName(child, 'key');
        if (!key) { return; }
        // Strip quotes for string-keyed pairs
        const keyText = key.text.replace(/^["'`]|["'`]$/g, '');
        if (!NOSQL_DANGEROUS_OPERATORS.has(keyText)) { return; }
        const value = childForFieldName(child, 'value');
        if (value) {
          const strength = this._expressionTaintStrength(value, state);
          if (strength !== false) {
            found = child;
            foundStrength = this._containsDirectTaint(value, state) ? 'direct' : strength;
            return false;
          }
        }
      });
      if (found) {
        return {
          node,
          sinkName: `${fullName}({ ${this._extractDangerousOperatorName(found) ?? '$where'}: <tainted> })`,
          sinkKind: 'nosql',
          isSanitized: false,
          chainStrength: foundStrength,
        };
      }
    }
    return null;
  }

  private _extractDangerousOperatorName(pair: SyntaxNode): string | null {
    const key = childForFieldName(pair, 'key');
    if (!key) { return null; }
    return key.text.replace(/^["'`]|["'`]$/g, '');
  }

  private _containsDirectTaint(node: SyntaxNode, state: ScopeState): boolean {
    let found = false;
    walkAst(node, (child) => {
      if (found) { return false; }
      if (this._expressionTaintStrength(child, state) === 'direct') {
        found = true;
        return false;
      }
    });
    return found;
  }

  /**
   * Returns true if the expression contains any reference (identifier, member,
   * unknown call) that we cannot prove is trusted. Used to gate medium-confidence
   * dynamic-sink reports so we don't double-flag arguments whose constituents
   * have already been validated/sanitized.
   *
   * Trusted: pure literals, sanitized symbols, known sanitizer/validator calls.
   * Untrusted: anything else (be conservative).
   */
  private _hasUntrustedDynamicParts(node: SyntaxNode | undefined, state: ScopeState): boolean {
    if (!node) { return false; }

    // Pure literal types — inherently trusted (no dynamic content)
    if (this._isPureLiteralType(node.type)) { return false; }

    // Symbol-level check: sanitized identifier/member is trusted
    const symbol = this._normalizeSymbol(node.text);
    if (symbol && state.sanitized.has(symbol)) { return false; }

    // Known sanitizer/validator calls produce trusted values
    if (isFunctionCall(node)) {
      const name = getCallName(node);
      if (SANITIZER_NAME_PATTERN.test(name) || VALIDATION_NAME_PATTERN.test(name)) {
        return false;
      }
      // Other function calls — return value is unknown, treat as untrusted
      return true;
    }

    // Bare identifier not in sanitized set → untrusted
    if (node.type === 'identifier') { return true; }

    // Composite — recurse through named children
    const childCount = namedChildCount(node);
    if (childCount === 0) {
      // Unknown leaf type — be conservative and treat as untrusted only if
      // it looks like an identifier (text starts with letter/underscore).
      return /^[A-Za-z_$]/.test(node.text);
    }
    for (let i = 0; i < childCount; i++) {
      const child = namedChild(node, i);
      if (child && this._hasUntrustedDynamicParts(child, state)) {
        return true;
      }
    }
    return false;
  }

  private _isPureLiteralType(type: string): boolean {
    return type === 'string' ||
      type === 'string_literal' ||
      type === 'number' ||
      type === 'integer' ||
      type === 'float' ||
      type === 'true' ||
      type === 'false' ||
      type === 'null' ||
      type === 'nil' ||
      type === 'undefined' ||
      type === 'numeric_literal' ||
      type === 'boolean_literal' ||
      type === 'null_literal';
  }

  private _isDynamicSqlExpression(node: SyntaxNode | undefined): boolean {
    if (!node) { return false; }
    const text = node.text;
    if (!/\b(select|insert|update|delete|where|from|drop|alter|create)\b/i.test(text)) {
      return false;
    }
    return node.type === 'binary_expression' ||
      node.type === 'additive_expression' ||
      node.type === 'template_string' ||
      node.type === 'string_literal' && text.includes('$') ||
      text.includes('${') ||
      /["'`]\s*\+|\+\s*["'`]/.test(text) ||
      /\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\})/.test(text);
  }

  private _isDynamicSqlExpressionWithState(node: SyntaxNode | undefined, state: ScopeState): boolean {
    if (!node) { return false; }
    const symbol = this._normalizeSymbol(node.text);
    if (symbol && state.dynamicSql.has(symbol)) { return true; }
    if (this._isDynamicSqlExpression(node)) { return true; }

    for (let i = 0; i < namedChildCount(node); i++) {
      const child = namedChild(node, i);
      if (child && this._isDynamicSqlExpressionWithState(child, state)) {
        return true;
      }
    }
    return false;
  }

  private _isDynamicExpression(node: SyntaxNode | undefined, state: ScopeState): boolean {
    if (!node || this._isSanitizedExpression(node, state)) { return false; }
    const trimmed = node.text.trim();
    if (/^(['"`])(?:\\.|(?!\1).)*\1$/.test(trimmed) && !trimmed.includes('${')) {
      return false;
    }
    return true;
  }

  private _normalizeSymbol(raw: string): string | null {
    const trimmed = raw.trim();
    if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(trimmed)) {
      return trimmed;
    }
    if (/^[A-Za-z_$][A-Za-z0-9_$.]*(?:\[[^\]]+\])?$/.test(trimmed)) {
      return trimmed.replace(/\s+/g, '');
    }
    return null;
  }
}
