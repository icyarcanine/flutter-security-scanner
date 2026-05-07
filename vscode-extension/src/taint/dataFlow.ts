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

export type SinkKind = 'sql' | 'command' | 'code' | 'html' | 'template' | 'url' | 'path' | 'redirect' | 'nosql' | 'header';

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
  /** Source → sink provenance steps; empty when the chain is just the sink itself. */
  pathSteps?: TaintProvenanceStep[];
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

/**
 * One step in the source → sink chain we surface to users. Same shape as
 * `PathStep` in models/finding.ts; redeclared locally to avoid the engine
 * importing into the core models layer.
 */
export interface TaintProvenanceStep {
  line: number;
  column?: number;
  label: string;
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
  /** Symbols sanitized for every modeled sink kind (numeric coercion, validators, sanitizing replace). */
  sanitized: Set<string>;
  /**
   * §QW-1 — symbols sanitized only for a specific subset of sink kinds.
   * `escapeHtml(x)` flowing into HTML is safe; the same value into SQL is not.
   * Entries here are NEVER short-circuited in `_expressionTaintStrength`; sink
   * checks consult this map to decide per-kind safety.
   */
  sanitizedFor: Map<string, Set<SinkKind>>;
  /**
   * §QW-41 — symbols proven to be in an allowlist past a `if (!barrier(x)) return;`
   * (or throw/continue/break). Maps symbol → first line on or after which the
   * guard's clearance applies. Populated as a pre-pass over the scope's
   * top-level statements; consulted by sink checks via the symbol's node line.
   */
  negateGuardedAfter: Map<string, number>;
  dynamicSql: Set<string>;
  /** Alias depth for directly tainted symbols. Direct sources start at 0. */
  taintDepth: Map<string, number>;
  /** Literal properties present when an object/array was created. */
  literalProperties: Map<string, Set<string>>;
  /** Properties known to contain tainted values, e.g. `parts[0]`. */
  taintedProperties: Map<string, Set<string>>;
  /** Objects mutated from a tainted Object.assign source. */
  objectAssignTainted: Set<string>;
  /** Symbols known to hold URLSearchParams instances. */
  urlSearchParamsSymbols: Set<string>;
  /**
   * Names that are assigned inside a conditional block (if/else/switch/loop/try/ternary).
   * For these we refuse to trust sanitization because the sanitizing assignment
   * may not execute on every path. They can still be marked tainted, but never
   * promoted to sanitized.
   */
  conditionallyAssigned: Set<string>;
  /**
   * Per-symbol provenance: the chain of `[line, label]` pairs explaining how
   * a symbol became tainted. Populated when:
   *   - A parameter is seeded (first step: "tainted via <param-name> parameter").
   *   - An assignment propagates taint from a tainted RHS to an LHS symbol
   *     (next step: "<lhs> = <rhs-text>" with the assignment's line).
   * On a sink hit, we copy the source argument's chain into the finding.
   */
  provenance: Map<string, TaintProvenanceStep[]>;
}

/** Maximum direct alias depth before taint downgrades to indirect. */
const MAX_TAINT_DEPTH = 3;

/**
 * Parameter names that are *always* treated as attacker-controlled when
 * present. `req`/`request` are unambiguous Express/Koa/Fastify handler
 * conventions; `userInput` is verbose-and-explicit ("this comes from the
 * user"). Together: names that almost no helper function would adopt by
 * accident.
 */
const STRONG_SOURCE_PARAMETER_NAMES = new Set(['req', 'request', 'userInput']);
/**
 * Parameter names that *might* be attacker-controlled but are also common in
 * pure helper functions (`function processData(data: number[])`,
 * `function transform(input: string)`). We only treat these as tainted when
 * corroborating evidence is present in the same function signature — e.g.,
 * a sibling `res`/`response`/`next` parameter that strongly implies an
 * Express-style request handler. Without that evidence they're left
 * untainted to avoid massive false-positive blasts.
 */
const HEURISTIC_SOURCE_PARAMETER_NAMES = new Set(['input', 'data', 'payload']);
const HANDLER_SHAPE_SIBLING_NAMES = new Set(['res', 'response', 'next', 'reply', 'ctx']);

/**
 * Token-level keyword set used by `_receiverLooksLikeDb` for the SQL-sink
 * receiver heuristic. Match is per-token (after camelCase splitting) so
 * `myDb`, `dbClient`, `pgPool` all hit, while unrelated names whose names
 * happen to embed these letters mid-token (`description`, `dbus`, `debit`)
 * do not. Add new ORM receivers here as the ecosystem grows.
 */
const DB_RECEIVER_KEYWORDS = new Set([
  'db', 'database', 'sqlite', 'sqlite3', 'conn', 'connection', 'client',
  'pool', 'cursor', 'tx', 'txn', 'batch', 'knex', 'pg', 'postgres',
  'postgresql', 'mysql', 'mssql', 'oracle', 'sequelize', 'prisma',
  'drizzle', 'orm', 'stmt', 'statement', 'mariadb', 'sqlserver',
  'redshift', 'cockroach', 'planetscale', 'neon', 'libsql', 'turso',
]);
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
  /(?:^|\.)(validate|validated|assertValid|assertSafe|ensureValid|ensureSafe|checkValid|checkSafe|isAllowed|schema\.parse|safeParse)$/i;
/**
 * Numeric coercion sanitizers. Their output is a JS number, which cannot
 * carry SQL/shell/path/template payloads. We treat them as full sanitizers
 * for every sink kind currently modeled — separated from the generic
 * validator list to make the rationale explicit and to make future
 * sink-specific gating (if precision data motivates it) a one-line change.
 * Keep this list tight: only functions whose return value is *guaranteed*
 * to be a number (not Number-like strings) belong here.
 */
const NUMERIC_COERCION_PATTERN =
  /(?:^|\.)(parseInt|parseFloat|Number|Number\.parseInt|Number\.parseFloat)$/;

const ALL_SINK_KINDS_LIST: SinkKind[] = [
  'sql', 'command', 'code', 'html', 'template', 'url', 'path', 'redirect', 'nosql', 'header',
];
const ALL_SINK_KINDS: ReadonlySet<SinkKind> = new Set<SinkKind>(ALL_SINK_KINDS_LIST);

/**
 * §QW-1 / §PR-6 — sink-specific sanitizer applicability. Each entry maps a
 * call-name pattern to the sink kinds the call's output is safe for.
 * Order matters: more-specific patterns first so generic catch-alls don't
 * shadow them. The numeric coercion / validator / sanitizing-replace paths
 * remain full-spectrum sanitizers and are handled outside this list.
 */
const SINK_SPECIFIC_SANITIZERS: ReadonlyArray<{
  readonly pattern: RegExp;
  readonly kinds: ReadonlySet<SinkKind>;
}> = [
  { pattern: /(?:^|\.)(escapeHtml|encodeHTML|sanitizeHtml)$/i, kinds: new Set<SinkKind>(['html']) },
  { pattern: /(?:^|\.)(?:dompurify)\.sanitize$/i, kinds: new Set<SinkKind>(['html']) },
  { pattern: /(?:^|\.)(?:validator)\.escape$/i, kinds: new Set<SinkKind>(['html']) },
  { pattern: /(?:^|\.)(encodeURI|encodeURIComponent)$/i, kinds: new Set<SinkKind>(['url', 'redirect', 'header']) },
  { pattern: /(?:^|\.)escapeSql$/i, kinds: new Set<SinkKind>(['sql']) },
  { pattern: /(?:^|\.)(?:sqlstring|mysql|pg)\.escape$/i, kinds: new Set<SinkKind>(['sql']) },
  { pattern: /(?:^|\.)(escapeShell|shellEscape)$/i, kinds: new Set<SinkKind>(['command']) },
];


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

          const sink = this._sinkForCall(node, scope);
          if (sink) {
            const isSanitized = this._isSanitizedSinkCall(node, sink, state);
            const strength = this._callReceivesTaint(node, sink, state);
            if (strength !== false) {
              const pathSteps = this.buildPathSteps(node, sink.name, state);
              findings.push({
                node, sinkName: sink.name, sinkKind: sink.kind,
                isSanitized, chainStrength: strength, pathSteps,
              });
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
          const sink = this._sinkForCall(node, scope);
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
          for (const [sym, kinds] of parentState.sanitizedFor) {
            const merged = state.sanitizedFor.get(sym);
            if (merged) {
              for (const k of kinds) { merged.add(k); }
            } else {
              state.sanitizedFor.set(sym, new Set(kinds));
            }
          }
          for (const [sym, line] of parentState.negateGuardedAfter) {
            const existing = state.negateGuardedAfter.get(sym);
            if (existing === undefined || line < existing) {
              state.negateGuardedAfter.set(sym, line);
            }
          }
          for (const d of parentState.dynamicSql) { state.dynamicSql.add(d); }
          for (const [sym, depth] of parentState.taintDepth) { state.taintDepth.set(sym, depth); }
          this._mergePropertyMap(state.literalProperties, parentState.literalProperties);
          this._mergePropertyMap(state.taintedProperties, parentState.taintedProperties);
          for (const sym of parentState.objectAssignTainted) { state.objectAssignTainted.add(sym); }
          for (const [sym, steps] of parentState.provenance) {
            if (!state.provenance.has(sym)) { state.provenance.set(sym, [...steps]); }
          }
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
    const provenance = new Map<string, TaintProvenanceStep[]>();

    const scopeLine = scope.startPosition.row + 1;

    // Direct identifier params. `req`/`request` are seeded unconditionally;
    // ambiguous names (`data`, `payload`, `input`, `userInput`) require
    // corroborating evidence that the function is a request handler — namely
    // a sibling parameter named `res`/`response`/`next`/`reply`/`ctx`.
    const paramNames = getFunctionParameterNames(scope);
    const hasHandlerSibling = paramNames.some(n => HANDLER_SHAPE_SIBLING_NAMES.has(n));
    for (const name of paramNames) {
      if (STRONG_SOURCE_PARAMETER_NAMES.has(name) ||
          (hasHandlerSibling && HEURISTIC_SOURCE_PARAMETER_NAMES.has(name))) {
        tainted.add(name);
        taintDepth.set(name, 0);
        provenance.set(name, [{
          line: scopeLine,
          label: `tainted source: '${name}' parameter (assumed user-controlled)`,
        }]);
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
          provenance.set(name, [{
            line: scopeLine,
            label: `tainted source: '${name}' destructured from request`,
          }]);
        }
      }
    }

    const conditionallyAssigned = this._collectConditionallyAssigned(scope);
    const negateGuardedAfter = this._collectNegateGuards(scope);
    return {
      tainted,
      weakTainted: new Set<string>(),
      sanitized: new Set<string>(),
      sanitizedFor: new Map<string, Set<SinkKind>>(),
      negateGuardedAfter,
      dynamicSql: new Set<string>(),
      taintDepth,
      literalProperties: new Map<string, Set<string>>(),
      taintedProperties: new Map<string, Set<string>>(),
      objectAssignTainted: new Set<string>(),
      urlSearchParamsSymbols: new Set<string>(),
      conditionallyAssigned,
      provenance,
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

  /**
   * §QW-41 — pre-pass: walks the scope's top-level statements looking for
   * `if (!barrier(x)) earlyExit;` patterns. After such a guard, `x` has been
   * proven to be in the allowlist and is sanitized for all sink kinds in the
   * dominated region. We track only top-level guards (siblings of the body
   * block); guards inside nested blocks are deferred to §EN-4's CFG, when it
   * lands. Returns `Map<symbol, firstGuaranteedLine>`.
   */
  private _collectNegateGuards(scope: SyntaxNode): Map<string, number> {
    const result = new Map<string, number>();
    const body = this._functionBody(scope);
    if (!body) { return result; }

    for (let i = 0; i < namedChildCount(body); i++) {
      const stmt = namedChild(body, i);
      if (!stmt || stmt.type !== 'if_statement') { continue; }
      if (!this._ifConsequenceIsEarlyExit(stmt)) { continue; }

      const test = this._unwrapParenthesized(this._ifTest(stmt));
      if (!test) { continue; }
      const symbols = this._extractNegateBarrierSymbols(test);
      if (symbols.length === 0) { continue; }

      const lineAfter = stmt.endPosition.row + 2;
      for (const sym of symbols) {
        const existing = result.get(sym);
        if (existing === undefined || lineAfter < existing) {
          result.set(sym, lineAfter);
        }
      }
    }
    return result;
  }

  private _functionBody(scope: SyntaxNode): SyntaxNode | null {
    const named = childForFieldName(scope, 'body');
    if (named && (named.type === 'statement_block' || named.type === 'block' || named.type === 'function_body')) {
      return named;
    }
    for (let i = 0; i < namedChildCount(scope); i++) {
      const child = namedChild(scope, i);
      if (!child) { continue; }
      if (child.type === 'statement_block' || child.type === 'block' || child.type === 'function_body') {
        return child;
      }
    }
    return scope;
  }

  private _ifTest(ifNode: SyntaxNode): SyntaxNode | null {
    const named = childForFieldName(ifNode, 'condition') ?? childForFieldName(ifNode, 'test');
    if (named) { return named; }
    for (let i = 0; i < namedChildCount(ifNode); i++) {
      const child = namedChild(ifNode, i);
      if (!child) { continue; }
      if (child.type === 'parenthesized_expression') { return child; }
    }
    return null;
  }

  private _ifConsequence(ifNode: SyntaxNode): SyntaxNode | null {
    const named = childForFieldName(ifNode, 'consequence') ?? childForFieldName(ifNode, 'consequent') ?? childForFieldName(ifNode, 'body');
    if (named) { return named; }
    let seenTest = false;
    for (let i = 0; i < namedChildCount(ifNode); i++) {
      const child = namedChild(ifNode, i);
      if (!child) { continue; }
      if (!seenTest && child.type === 'parenthesized_expression') {
        seenTest = true;
        continue;
      }
      if (seenTest && child.type !== 'else_clause') { return child; }
    }
    return null;
  }

  private _unwrapParenthesized(node: SyntaxNode | null): SyntaxNode | null {
    let current = node;
    while (current && current.type === 'parenthesized_expression') {
      const inner = namedChild(current, 0);
      if (!inner) { break; }
      current = inner;
    }
    return current;
  }

  /**
   * Returns true when the if-statement's consequence is guaranteed to exit
   * the surrounding statement (`return`, `throw`, `continue`, `break`). Handles
   * single-statement bodies (`if (x) return;`) and block bodies whose last
   * non-trivial statement is the early exit.
   */
  private _ifConsequenceIsEarlyExit(ifNode: SyntaxNode): boolean {
    const consequence = this._ifConsequence(ifNode);
    if (!consequence) { return false; }
    return this._statementIsEarlyExit(consequence);
  }

  private _statementIsEarlyExit(node: SyntaxNode): boolean {
    if (node.type === 'return_statement' || node.type === 'throw_statement' ||
        node.type === 'continue_statement' || node.type === 'break_statement') {
      return true;
    }
    if (node.type === 'statement_block' || node.type === 'block') {
      for (let i = namedChildCount(node) - 1; i >= 0; i--) {
        const child = namedChild(node, i);
        if (!child) { continue; }
        if (child.type === 'comment') { continue; }
        return this._statementIsEarlyExit(child);
      }
      return false;
    }
    if (node.type === 'expression_statement') {
      const inner = namedChild(node, 0);
      return inner ? this._statementIsEarlyExit(inner) : false;
    }
    return false;
  }

  /**
   * Recognizes negate-guard barrier patterns and returns the symbol(s) the
   * guard proves are in the allowlist. Supported shapes:
   *   - !X.has(sym)          — Set / Map membership negation
   *   - !X.includes(sym)     — Array membership negation
   *   - !X.test(sym)         — RegExp negation (treated as allowlist)
   *   - !X.hasOwnProperty(sym)
   *   - X.indexOf(sym) === -1 / !== -1 / < 0
   *   - !ALLOW[sym]          — object-key negation
   * Combined `&& / ||` clauses are not handled; the caller should pre-unwrap.
   */
  private _extractNegateBarrierSymbols(testNode: SyntaxNode | null): string[] {
    if (!testNode) { return []; }
    const text = testNode.text.replace(/\s+/g, '');
    const symbols: string[] = [];

    let m = text.match(/^!\w+(?:\.\w+)*\.(?:has|includes|test|hasOwnProperty)\(([A-Za-z_$][A-Za-z0-9_$.]*)\)$/);
    if (m && m[1]) { symbols.push(m[1]); return symbols; }

    m = text.match(/^!\w+(?:\.\w+)*\[([A-Za-z_$][A-Za-z0-9_$.]*)\]$/);
    if (m && m[1]) { symbols.push(m[1]); return symbols; }

    m = text.match(/^\w+(?:\.\w+)*\.indexOf\(([A-Za-z_$][A-Za-z0-9_$.]*)\)(?:===-1|!==-1|<0)$/);
    if (m && m[1]) { symbols.push(m[1]); return symbols; }

    return symbols;
  }

  /**
   * §QW-2 — collects `instanceof T` narrowings from any if-statement whose
   * consequent dominates `node` (within `scope`). Returns `Map<symbol, T>`.
   * Without §EN-4's CFG we approximate domination by: the node lives inside
   * the if's consequence subtree, and the test is a (possibly &&-conjoined)
   * `x instanceof T` expression. Else-branch and `||`-conjoined cases are
   * intentionally excluded — they don't establish the narrowing for the
   * main branch.
   */
  private _findEnclosingInstanceofNarrowings(node: SyntaxNode, scope: SyntaxNode): Map<string, string> {
    const narrowings = new Map<string, string>();
    let current: SyntaxNode | null = node;
    while (current && current !== scope) {
      const parent: SyntaxNode | null = current.parent;
      if (!parent) { break; }
      if (parent.type === 'if_statement') {
        const consequence = this._ifConsequence(parent);
        if (consequence && this._isAncestorOrSelf(consequence, current)) {
          const test = this._unwrapParenthesized(this._ifTest(parent));
          this._collectInstanceofFromTest(test, narrowings);
        }
      }
      current = parent;
    }
    return narrowings;
  }

  private _isAncestorOrSelf(ancestor: SyntaxNode, candidate: SyntaxNode): boolean {
    let current: SyntaxNode | null = candidate;
    while (current) {
      if (current === ancestor) { return true; }
      current = current.parent;
    }
    return false;
  }

  private _collectInstanceofFromTest(testNode: SyntaxNode | null, out: Map<string, string>): void {
    if (!testNode) { return; }
    const inner = this._unwrapParenthesized(testNode);
    if (!inner) { return; }
    if (inner.type === 'binary_expression') {
      const operator = childForFieldName(inner, 'operator');
      const opText = operator ? operator.text : this._inferBinaryOperator(inner);
      if (opText === 'instanceof') {
        const left = childForFieldName(inner, 'left') ?? namedChild(inner, 0);
        const right = childForFieldName(inner, 'right') ?? namedChild(inner, 1);
        if (left && right) {
          const sym = this._normalizeSymbol(left.text);
          const typeName = right.text.trim();
          if (sym && typeName && !out.has(sym)) {
            out.set(sym, typeName);
          }
        }
      } else if (opText === '&&') {
        const left = childForFieldName(inner, 'left') ?? namedChild(inner, 0);
        const right = childForFieldName(inner, 'right') ?? namedChild(inner, 1);
        this._collectInstanceofFromTest(left, out);
        this._collectInstanceofFromTest(right, out);
      }
    }
  }

  private _inferBinaryOperator(node: SyntaxNode): string {
    const text = node.text;
    if (/\binstanceof\b/.test(text)) { return 'instanceof'; }
    if (/&&/.test(text) && !/\|\|/.test(text)) { return '&&'; }
    return '';
  }

  private _propagateAssignment(node: SyntaxNode, lang: string, state: ScopeState): void {
    const targets = getAssignmentNames(node, lang)
      .map(name => this._normalizeSymbol(name))
      .filter((name): name is string => name != null);
    if (targets.length === 0) { return; }

    const value = getAssignmentValue(node);
    const sanitizedKinds = value != null ? this._expressionSanitizedKinds(value, state) : null;
    const isSanitized = sanitizedKinds !== null && sanitizedKinds.size > 0;
    const isFullySanitized = isSanitized && sanitizedKinds!.size === ALL_SINK_KINDS_LIST.length;
    const strength = value != null ? this._expressionTaintStrength(value, state) : false;
    const isDynamicSql = value != null && this._isDynamicSqlExpressionWithState(value, state);
    const augmented = isAugmentedAssignment(node);
    const literalProperties = value ? this._literalPropertyNames(value) : null;
    const taintedProperties = value ? this._literalTaintedPropertyNames(value, state) : new Set<string>();
    const isUrlSearchParams = value ? this._isUrlSearchParamsExpression(value) : false;

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

        if (isUrlSearchParams) {
          state.urlSearchParamsSymbols.add(target);
        } else {
          state.urlSearchParamsSymbols.delete(target);
        }
      }

      if (strength !== false && !isFullySanitized) {
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
        // §QW-1 — partial sanitization on a tainted RHS still records the
        // covered sink kinds so a later same-kind sink check trusts the LHS.
        if (isSanitized && !isConditional && !augmented) {
          state.sanitizedFor.set(target, new Set(sanitizedKinds!));
        } else {
          state.sanitizedFor.delete(target);
        }
        // Append a propagation step to the target's provenance. We seed the
        // chain from whichever RHS symbol contributes (first-found wins —
        // good enough for an explanatory trail).
        if (value) {
          const rhsProvenance = this._collectRhsProvenance(value, state);
          const assignLine = node.startPosition.row + 1;
          const assignText = node.text.length > 80 ? node.text.slice(0, 77) + '…' : node.text;
          const newSteps: TaintProvenanceStep[] = [
            ...rhsProvenance,
            { line: assignLine, label: `propagated: ${assignText}` },
          ];
          state.provenance.set(target, newSteps);
        }
      } else if (isFullySanitized) {
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
          state.sanitizedFor.delete(target);
          state.provenance.delete(target);
        }
      } else if (isSanitized) {
        // Partial sanitizer (e.g. escapeHtml) on an otherwise-clean value:
        // record the kinds it covers without disturbing existing taint state.
        if (!isConditional && !augmented) {
          state.sanitizedFor.set(target, new Set(sanitizedKinds!));
          state.sanitized.delete(target);
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
          state.sanitizedFor.delete(target);
          state.provenance.delete(target);
        }
      }

      if (isDynamicSql && !isFullySanitized) {
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
    if (!VALIDATION_NAME_PATTERN.test(name) && !NUMERIC_COERCION_PATTERN.test(name)) { return; }

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

    // Sanitized symbols are never tainted (full sanitization only — partial
    // sanitization is handled at sink time by `_isSanitizedSinkCall`).
    if (symbol && state.sanitized.has(symbol)) { return false; }

    // §QW-41 — symbols past a `if (!barrier(x)) return;` guard are sanitized
    // for all sinks in the dominated region.
    if (symbol) {
      const guardLine = state.negateGuardedAfter.get(symbol);
      if (guardLine !== undefined && node.startPosition.row + 1 >= guardLine) {
        return false;
      }
    }

    // Direct symbol taint — strongest signal.
    if (symbol && state.tainted.has(symbol)) { return 'direct'; }

    // Indirect symbol taint.
    if (symbol && state.weakTainted.has(symbol)) { return 'indirect'; }

    // Sanitizer/validator call — trusted output ONLY when the call clears
    // every modeled sink kind (numeric coercion, generic validators, sanitizing
    // replace, blanket sanitize/clean/normalize). Partial sanitizers like
    // `escapeHtml(...)` deliberately do not short-circuit here so the inner
    // taint flows through to the sink-time per-kind check, which then decides
    // if the partial coverage matches the actual sink kind.
    const exprSanitizedKinds = this._expressionSanitizedKinds(node, state);
    if (exprSanitizedKinds && exprSanitizedKinds.size === ALL_SINK_KINDS_LIST.length) {
      return false;
    }

    // Recognized direct source expressions (req.body.x, request.args.get(), etc.)
    if (this._isDirectSourceExpression(node)) { return 'direct'; }

    if (symbol) {
      const propertyStrength = this._memberPropertyTaintStrength(symbol, state);
      if (propertyStrength) { return propertyStrength; }
    }

    // Symbol is a base object with tainted properties (e.g. `cfg` when `cfg.id` is tainted).
    if (symbol && this._isObjectTainted(symbol, state)) { return 'indirect'; }

    const builtinStrength = this._builtinCallTaintStrength(node, state);
    if (builtinStrength !== null) { return builtinStrength; }

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
        if (this._isFunctionLikeExpression(first)) {
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

  private _isSanitizedExpression(node: SyntaxNode | null, state: ScopeState, sinkKind?: SinkKind): boolean {
    const kinds = this._expressionSanitizedKinds(node, state);
    if (!kinds || kinds.size === 0) { return false; }
    if (sinkKind === undefined) { return true; }
    return kinds.has(sinkKind);
  }

  /**
   * §QW-1 — returns the set of sink kinds the given expression is sanitized
   * for, or null when the expression is not sanitized at all. Symbol-level
   * full sanitization (numeric coercion, validators, sanitizing replace) maps
   * to ALL_SINK_KINDS; partial sanitizers (escapeHtml, encodeURIComponent…)
   * map to a narrower set drawn from `SINK_SPECIFIC_SANITIZERS`.
   */
  private _expressionSanitizedKinds(node: SyntaxNode | null, state: ScopeState): ReadonlySet<SinkKind> | null {
    if (!node) { return null; }
    const symbol = this._normalizeSymbol(node.text);
    if (symbol) {
      if (state.sanitized.has(symbol)) { return ALL_SINK_KINDS; }
      const partial = state.sanitizedFor.get(symbol);
      if (partial && partial.size > 0) { return partial; }
      const guardLine = state.negateGuardedAfter.get(symbol);
      if (guardLine !== undefined && node.startPosition.row + 1 >= guardLine) {
        return ALL_SINK_KINDS;
      }
    }

    if (this._isNumericCoercionExpression(node)) { return ALL_SINK_KINDS; }

    if (isFunctionCall(node)) {
      const name = getCallName(node);
      if (this._isSanitizingReplaceCall(node, name)) { return ALL_SINK_KINDS; }
      const callKinds = this._sanitizerCallKinds(name);
      if (callKinds) { return callKinds; }
    }

    return null;
  }

  /**
   * §QW-1 — maps a call name to its `sanitizesFor` sink-kind set. Numeric
   * coercion / generic validators / generic catch-all sanitizers are full
   * coverage; the entries in `SINK_SPECIFIC_SANITIZERS` are partial.
   */
  private _sanitizerCallKinds(name: string): ReadonlySet<SinkKind> | null {
    if (NUMERIC_COERCION_PATTERN.test(name)) { return ALL_SINK_KINDS; }
    if (VALIDATION_NAME_PATTERN.test(name)) { return ALL_SINK_KINDS; }
    for (const entry of SINK_SPECIFIC_SANITIZERS) {
      if (entry.pattern.test(name)) { return entry.kinds; }
    }
    if (SANITIZER_NAME_PATTERN.test(name)) { return ALL_SINK_KINDS; }
    return null;
  }

  /**
   * JavaScript numeric coercion idioms. These force a value into a number,
   * which is safe for string-injection sinks in the same way parseInt is.
   */
  private _isNumericCoercionExpression(node: SyntaxNode): boolean {
    const text = node.text.trim();

    if (node.type === 'unary_expression') {
      if (/^\+\s*/.test(text)) { return true; }
      if (/^~\s*~\s*/.test(text)) { return true; }
    }

    if (node.type === 'binary_expression') {
      if (/\|\s*0\s*$/.test(text)) { return true; }
      if (/>>>\s*0\s*$/.test(text)) { return true; }
    }

    // Parser fallback / cross-language AST type drift: keep a tight textual
    // fallback so `(req.body.id | 0)` still sanitizes even if the node type
    // changes under tree-sitter.
    const stripped = text.replace(/^\(+|\)+$/g, '').trim();
    return /^\+\s*[^+]/.test(stripped) ||
      /^~\s*~\s*/.test(stripped) ||
      /\|\s*0\s*$/.test(stripped) ||
      />>>\s*0\s*$/.test(stripped);
  }

  private _builtinCallTaintStrength(node: SyntaxNode, state: ScopeState): ChainStrength | false | null {
    if (!isFunctionCall(node)) { return null; }
    const name = getCallName(node).replace(/\s+/g, '');
    const args = getCallArguments(node);

    if (/^(?:JSON\.)?(?:parse|stringify)$/i.test(name) ||
        /^(?:Buffer\.)?from$/i.test(name)) {
      return this._strongestTaint(args, state);
    }

    if (/(?:^|\.)get$/i.test(name) && this._isUrlSearchParamsGet(name, node, state)) {
      return 'direct';
    }

    return null;
  }

  private _strongestTaint(nodes: SyntaxNode[], state: ScopeState): ChainStrength | false {
    let best: ChainStrength | false = false;
    for (const arg of nodes) {
      const s = this._expressionTaintStrength(arg, state);
      if (s === 'direct') { return 'direct'; }
      if (s === 'indirect') { best = 'indirect'; }
    }
    return best;
  }

  private _isUrlSearchParamsExpression(node: SyntaxNode): boolean {
    const compact = node.text.replace(/\s+/g, '');
    return /\bnewURLSearchParams\(/.test(compact) ||
      /\.searchParams\b/.test(compact) ||
      /\bURLSearchParams\(/.test(compact);
  }

  private _isUrlSearchParamsGet(callName: string, node: SyntaxNode, state: ScopeState): boolean {
    const receivers = [
      callName.replace(/\.get$/i, ''),
      node.text.replace(/\s+/g, '').replace(/\.get\([\s\S]*$/i, ''),
    ].filter(Boolean);
    for (const receiver of receivers) {
      if (/URLSearchParams|\.searchParams$/i.test(receiver)) { return true; }
      const symbol = this._normalizeSymbol(receiver);
      if (symbol != null && state.urlSearchParamsSymbols.has(symbol)) { return true; }
    }
    return false;
  }

  private _isSanitizingReplaceCall(node: SyntaxNode, callName: string): boolean {
    if (!/(?:^|\.)replace$/i.test(callName)) { return false; }
    const args = getCallArguments(node);
    if (args.length < 2) { return false; }
    const pattern = args[0].text.trim();
    const replacement = args[1].text.trim();
    if (!/^['"`]{2}$/.test(replacement)) { return false; }
    return /^\/\\D\/[gimyus]*$/.test(pattern) ||
      /^\/\[\^[A-Za-z0-9_\\\-\s]+\]\/[gimyus]*$/.test(pattern) ||
      /^\/\[\^\\w[\\.\-\s]*\]\/[gimyus]*$/.test(pattern);
  }

  private _isDirectSourceExpression(node: SyntaxNode): boolean {
    // Strip whitespace and treat optional-chaining (`?.`) the same as a
    // plain dot — `req?.query?.id` should be tracked just like `req.query.id`.
    // Also normalize bracket-notation (`req['body']['x']`) to dot-notation so
    // both styles fall through the same regexes.
    let compact = node.text.replace(/\s+/g, '').replace(/\?\./g, '.');
    compact = compact.replace(/\[(?:'([^']+)'|"([^"]+)")\]/g, (_m, a, b) => '.' + (a ?? b));

    // ── Node/Express + browser ────────────────────────────────────────────
    if (/^(?:req|request)\.(?:body|query|params|file|files)(?:\.|\[|$)/.test(compact)) {
      return true;
    }
    if (/^(?:req|request)\.(?:uri\.queryparameters|queryparameters|headers|cookies|signedCookies|session|rawHeaders)(?:\.|\[|$)/i.test(compact)) {
      return true;
    }
    if (/^process\.env(?:\.|\[|$)/.test(compact)) {
      return true;
    }
    if (/^(?:params|searchParams|urlParams|queryParams)\.get\(/i.test(compact)) {
      return true;
    }
    if (/^(?:process\.)?stdin(?:\.|\[|$)/i.test(compact)) {
      return true;
    }

    // ── Python frameworks ─────────────────────────────────────────────────
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

    // ── Dart / Flutter ────────────────────────────────────────────────────
    // Gemini correctly pointed out that the taint engine's Node/Express bias
    // left Dart sources essentially invisible. This block recognises the
    // idioms a real Flutter app uses to accept untrusted input: text field
    // controllers, deep-link query parameters, platform channel arguments,
    // route arguments, platform environment, stdin, and file pickers.
    if (/^(?:stdin|io\.stdin)\.readlinesync\(/i.test(compact)) {
      return true;
    }
    if (/^platform\.environment(?:\.|\[|$)/i.test(compact)) {
      return true;
    }
    // TextEditingController / TextField value access.
    // Matches `_nameController.text`, `emailController.value.text`,
    // `_searchField.text`, `userInput.text`, etc. The `controller|field|input`
    // disambiguator keeps us from flagging unrelated `.text` getters.
    if (/(?:^|\.)(?:text|value)(?:\.|\[|$)/.test(compact) && /controller|field|input|textediting/i.test(compact)) {
      return true;
    }
    // Uri.base.queryParameters / Uri.parse(...).queryParameters — the standard
    // way Flutter reads deep-link and web query string values.
    if (/(?:^|\.)queryparameters(?:all)?(?:\.|\[|$)/i.test(compact)) {
      return true;
    }
    // GoRouter / ModalRoute arguments — the common route parameter plumbing.
    if (/(?:^|\.)(?:pathparameters|pathparams|queryparameters|extra)(?:\.|\[|$)/i.test(compact)) {
      return true;
    }
    if (/\bmodalroute\.of\([^)]*\)[.!]?\.settings[.!]?\.arguments\b/i.test(compact)) {
      return true;
    }
    if (/\bgorouterstate\.(?:of|\w+)/i.test(compact) && /(?:params|pathparameters|queryparameters|extra)/i.test(compact)) {
      return true;
    }
    // Platform channel / MethodCall arguments — `call.arguments` inside an
    // `onMethodCall` handler, `methodChannel.invokeMethod(...)` return values
    // are harder to track statically, but `call.arguments` is unambiguous.
    if (/(?:^|\.)(?:methodcall|call)\.arguments(?:\.|\[|$)/i.test(compact)) {
      return true;
    }
    // Clipboard — anything pasted from the clipboard is attacker-controlled.
    if (/\bclipboard\.getdata\(/i.test(compact) || /(?:^|\.)clipboarddata(?:\.|\[|$)/i.test(compact)) {
      return true;
    }
    // File pickers — returned file paths are attacker-controlled (user can
    // pick any file; bypass controls via symlinks etc.).
    if (/\bfilepicker\.platform\.(?:pickfiles|pickdirectory|getfile)/i.test(compact)) {
      return true;
    }
    if (/\bimagepicker\(\)?\.pick(?:image|video|multiimage|media)/i.test(compact)) {
      return true;
    }
    // String.fromEnvironment / bool.fromEnvironment / int.fromEnvironment:
    // compile-time defines, treated as attacker-controlled for taint
    // purposes when they flow into a sink (an attacker building the app
    // can set these).
    if (/^(?:string|bool|int)\.fromenvironment\(/i.test(compact)) {
      return true;
    }
    // Dart's HttpRequest / shelf / frog Request
    if (/^(?:httprequest|request)\.(?:uri|headers|cookies|requestedUri)(?:\.|\[|$)/i.test(compact)) {
      return true;
    }

    return false;
  }

  private _markSanitized(node: SyntaxNode, state: ScopeState, kinds: ReadonlySet<SinkKind> = ALL_SINK_KINDS): void {
    const symbols = new Set<string>();
    const exact = this._normalizeSymbol(node.text);
    if (exact) { symbols.add(exact); }

    for (let i = 0; i < namedChildCount(node); i++) {
      const child = namedChild(node, i);
      if (!child) { continue; }
      const childSymbol = this._normalizeSymbol(child.text);
      if (childSymbol) { symbols.add(childSymbol); }
    }

    const isFull = kinds.size === ALL_SINK_KINDS_LIST.length;
    for (const symbol of symbols) {
      state.tainted.delete(symbol);
      state.weakTainted.delete(symbol);
      state.taintDepth.delete(symbol);
      if (isFull) {
        state.sanitized.add(symbol);
        state.sanitizedFor.delete(symbol);
      } else {
        state.sanitizedFor.set(symbol, new Set(kinds));
      }
    }
  }

  // ─── Sink detection ───────────────────────────────────────────────────────

  private _sinkForCall(node: SyntaxNode, scope?: SyntaxNode): SinkDefinition | null {
    const fullName = getCallName(node);
    const bareName = fullName.split('.').pop() ?? fullName;
    const lowerFull = fullName.toLowerCase();
    const lowerBare = bareName.toLowerCase();

    // SQL sinks. The set of method names is broad (`query`, `execute`,
    // `raw`, etc.) and overlaps with non-SQL APIs (e.g. analytics clients,
    // map-like containers, HTTP query builders). To keep precision high
    // we additionally require ONE of:
    //   (a) the bare name is unambiguous (`rawQuery`, `executescript`,
    //       `executemany`, `raw` — almost always SQL)
    //   (b) the receiver name looks DB-shaped (`db`, `database`, `sqlite`,
    //       `conn`, `connection`, `client`, `pool`, `txn`, `tx`, `batch`,
    //       `knex`, `pg`, `mysql`, `mongo` — but mongo is NoSQL handled
    //       separately, and we whitelist it for `find`/`update`)
    //   (c) the first argument is a string literal containing a SQL keyword
    //       (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `DROP`,
    //       `ALTER`).
    //   (d) §QW-2 — an enclosing `if (receiver instanceof T) { ... }` guard
    //       narrows the receiver to a DB-shaped type.
    // This mirrors the Dart-side heuristic in lib/src/taint/taint_engine.dart.
    if (['query', 'execute', 'executequery', 'raw', 'rawquery', 'executemany', 'executescript'].includes(lowerBare)) {
      const isUnambiguous = ['rawquery', 'executescript', 'executemany', 'raw'].includes(lowerBare);
      if (isUnambiguous) {
        return { name: fullName, kind: 'sql' };
      }
      if (this._receiverLooksLikeDb(fullName) ||
          this._firstArgIsSqlLiteral(node) ||
          (scope && this._receiverInstanceofImpliesDb(node, fullName, scope))) {
        return { name: fullName, kind: 'sql' };
      }
      // Bare `query(x)` / `execute(x)` with no DB-shaped receiver and no
      // SQL literal: too ambiguous, skip.
      return null;
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

    // Dynamic ESM import — `import(taint)` resolves and executes a module
    // identified by an attacker-controlled string. tree-sitter parses this as
    // a call_expression with `import` as the callee, so it surfaces here as
    // fullName === 'import'. CodeQL classifies this as the same `code-injection`
    // bucket (CWE-95) since the loaded module's top-level code runs.
    if (fullName === 'import' || lowerBare === 'import') {
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
    if (/^res\.redirect$/.test(fullName)) {
      return { name: fullName, kind: 'redirect' };
    }

    // Header injection / HTTP response splitting (CWE-113). Tainted strings
    // into header-setting APIs let an attacker inject `\r\n` and forge
    // arbitrary headers (or split the response body). `res.location` lives
    // here too — it sets the Location header, so it's both an open-redirect
    // and a header-injection sink. We treat it as `header` because the
    // CRLF risk is the more serious of the two.
    if (/^res\.(?:setHeader|header|cookie|location|writeHead|append)$/.test(fullName)) {
      return { name: fullName, kind: 'header' };
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

    // ── Dart / Flutter sinks ──────────────────────────────────────────────
    // Gemini's critique was right that the engine had full Node/Python
    // sinks but nothing for Dart. These cover the real exposure points in
    // a Flutter app: filesystem, subprocess, webview JS, URL launchers.

    // Dart File(...) / Directory(...) constructor — tainted path is a
    // direct path-traversal vulnerability. We match the constructor call
    // (`File(x)`, `Directory(x)`) by exact name rather than by method
    // suffix because method names like `File` are rare and unambiguous.
    if (bareName === 'File' || bareName === 'Directory') {
      return { name: fullName, kind: 'path' };
    }
    if (/^file\.(?:fromUri|fromRawPath)$/i.test(fullName)) {
      return { name: fullName, kind: 'path' };
    }
    // Flutter rootBundle load from a dynamic asset path.
    if (/^rootbundle\.(?:loadstring|load|loadbuffer|loadstructuredata|loadstructuredbinarydata)$/i.test(fullName)) {
      return { name: fullName, kind: 'path' };
    }

    // Dart Process.run / Process.start / Process.runSync — classic command
    // injection when the executable OR the argument list is tainted. The
    // sink slot is special here: `Process.run('sh', ['-c', tainted])` is
    // unsafe even though arg 0 is the shell — the taint engine's "first arg"
    // rule handles the executable case; for the argument-list case we fall
    // back to `_isDynamicSinkCall` which walks the whole call.
    if (/^process\.(?:run|start|runsync)$/i.test(fullName)) {
      return { name: fullName, kind: 'command' };
    }

    // WebView JavaScript evaluation — direct code execution in a webview
    // context. Dart webview APIs use several names across versions; we
    // cover the common ones.
    if (/(?:^|\.)(?:runjavascript|runjavascriptreturningresult|evaluatejavascript)$/i.test(fullName)) {
      return { name: fullName, kind: 'code' };
    }
    // WebView loading a dynamic URL — open redirect / phishing vector.
    if (/(?:^|\.)(?:loadurl|loadrequest|loadhtmlstring|loadflutterasset)$/i.test(fullName)) {
      return { name: fullName, kind: 'url' };
    }

    // url_launcher / launchUrl — opening an attacker-controlled URL can
    // trigger app-scheme hijacks or phishing.
    if (bareName === 'launchurl' || bareName === 'launch' ||
        lowerFull === 'urllauncher.launchurl' || lowerFull === 'urllauncher.launch') {
      return { name: fullName, kind: 'url' };
    }

    // Dart HTTP clients: http.get / http.post / Dio / Client().send / etc.
    // Tainted URL passed to these is SSRF (server-side) or arbitrary URL
    // fetch (client-side, still an exposure when combined with response
    // parsing).
    if (/^http\.(?:get|post|put|delete|patch|head|read|readbytes)$/i.test(fullName)) {
      return { name: fullName, kind: 'url' };
    }
    if (/(?:^|\.)dio\.(?:get|post|put|delete|patch|head|request|fetch|download)$/i.test(fullName)) {
      return { name: fullName, kind: 'url' };
    }
    if (/(?:^|\.)(?:httpclient|client)\.(?:getUrl|postUrl|putUrl|deleteUrl|patchUrl|headUrl|openurl)$/i.test(fullName)) {
      return { name: fullName, kind: 'url' };
    }

    // Navigator.pushNamed — route name injection. Treated as a url-kind
    // sink so the same "confirmed taint only" policy applies (dynamic
    // route names are common and mostly benign).
    if (/(?:^|\.)pushnamed(?:andremoveuntil|andremoveuntilnotransition)?$/i.test(fullName)) {
      return { name: fullName, kind: 'url' };
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

    const args = getCallArguments(node);
    if (args.length === 0) { return false; }

    // Whole-arg sanitization (`db.query(escapeSql(x))`) trumps everything.
    for (const arg of args) {
      if (this._isSanitizedExpression(arg, state, sink.kind)) { return true; }
    }

    // §QW-1 — leaf-level: ALL tainted leaves must be sanitized for sink.kind,
    // AND at least one tainted leaf must exist. Vacuously-clean args (no
    // tainted leaves at all) fall through with `false` so dynamic-SQL findings
    // aren't suppressed for argless dynamic composition.
    return this._allTaintedLeavesSanitizedForKind(args, state, sink.kind);
  }

  private _allTaintedLeavesSanitizedForKind(
    args: SyntaxNode[],
    state: ScopeState,
    sinkKind: SinkKind,
  ): boolean {
    let foundTainted = false;
    let unsanitizedFound = false;

    const visit = (n: SyntaxNode, isRoot: boolean): void => {
      if (unsanitizedFound) { return; }
      if (!isRoot && FUNCTION_SCOPE_TYPES.includes(n.type)) { return; }

      // Inline sanitizer call covering sink.kind: trust the output. Count its
      // tainted args as `foundTainted` so the parent can claim positive
      // sanitization, then stop descending.
      if (!isRoot && isFunctionCall(n)) {
        const name = getCallName(n);
        const callKinds = this._sanitizerCallKinds(name);
        const isCovering =
          (callKinds && callKinds.has(sinkKind)) ||
          this._isSanitizingReplaceCall(n, name) ||
          this._isNumericCoercionExpression(n);
        if (isCovering) {
          for (const inner of getCallArguments(n)) {
            if (this._expressionTaintStrength(inner, state) !== false) {
              foundTainted = true;
              break;
            }
          }
          return;
        }
      }

      const symbol = this._normalizeSymbol(n.text);
      if (symbol && (state.tainted.has(symbol) || state.weakTainted.has(symbol))) {
        foundTainted = true;
        if (state.sanitized.has(symbol)) { return; }
        const partial = state.sanitizedFor.get(symbol);
        if (partial && partial.has(sinkKind)) { return; }
        const guardLine = state.negateGuardedAfter.get(symbol);
        if (guardLine !== undefined && n.startPosition.row + 1 >= guardLine) { return; }
        unsanitizedFound = true;
        return;
      }

      for (let i = 0; i < namedChildCount(n); i++) {
        const child = namedChild(n, i);
        if (!child) { continue; }
        visit(child, false);
        if (unsanitizedFound) { return; }
      }
    };

    for (const arg of args) {
      visit(arg, true);
      if (unsanitizedFound) { return false; }
    }
    return foundTainted;
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
        if (this._isFunctionLikeExpression(args[0])) { return false; }
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
      case 'header':
        // Header values are routinely dynamic in legitimate code (timestamps,
        // session ids, content lengths). Flag only on confirmed taint flow
        // through the regular path.
        return false;
      case 'nosql':
        // Detected only via _checkNoSqlInjection structural check.
        return false;
    }
  }

  private _isFunctionLikeExpression(node: SyntaxNode | null): boolean {
    return node != null && (
      node.type === 'arrow_function' ||
      node.type === 'function' ||
      node.type === 'function_expression' ||
      node.type === 'function_declaration' ||
      node.type === 'lambda' ||
      node.type === 'lambda_expression'
    );
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
      if (SANITIZER_NAME_PATTERN.test(name) ||
          VALIDATION_NAME_PATTERN.test(name) ||
          NUMERIC_COERCION_PATTERN.test(name)) {
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

  /**
   * Find the first symbol on the RHS that has provenance and return a copy
   * of its chain. Stops at the first match — good enough to produce a
   * useful "Source → Sink" trace without exploding into a graph.
   */
  private _collectRhsProvenance(node: SyntaxNode, state: ScopeState): TaintProvenanceStep[] {
    let result: TaintProvenanceStep[] | null = null;
    walkAst(node, (child) => {
      if (result) { return false; }
      const sym = this._normalizeSymbol(child.text);
      if (sym && state.provenance.has(sym)) {
        result = [...state.provenance.get(sym)!];
        return false;
      }
    });
    return result ?? [];
  }

  /**
   * For a sink-receiving node, find a tainted argument and return its
   * provenance chain (with the sink itself appended as the final step).
   * Returns undefined when no tainted symbol is involved in the call.
   */
  public buildPathSteps(node: SyntaxNode, sinkName: string, state: ScopeState): TaintProvenanceStep[] | undefined {
    const args = getCallArguments(node);
    for (const arg of args) {
      if (!arg) { continue; }
      const provenance = this._collectRhsProvenance(arg, state);
      if (provenance.length > 0) {
        return [
          ...provenance,
          {
            line: node.startPosition.row + 1,
            column: node.startPosition.column + 1,
            label: `sink: ${sinkName}`,
          },
        ];
      }
    }
    return undefined;
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

  /**
   * Heuristic: returns true when the receiver name looks DB-shaped, i.e. the
   * call is plausibly a SQL query. Used to filter out unambiguous-method-name
   * collisions like a HTTP client's `query()` builder or a map's `execute`.
   *
   * `fullName` is something like `db.query`, `userClient.query`,
   * `getDb().query`, `myDb.query`, or just `query`. We:
   *   1. Strip the trailing method name.
   *   2. Tokenize the receiver on dot, bracket, underscore boundaries AND
   *      camelCase boundaries (so `myDbClient` → ['my', 'Db', 'Client']).
   *   3. Strip a single trailing `()` from method-chain receivers
   *      (`getDb()` → `getDb` → ['get', 'Db']).
   *   4. Match any token (case-insensitively) against the DB-keyword set.
   *
   * This catches `myDb`, `dbClient`, `pgPool`, `prismaClient`, `getDb()`,
   * `this._db`, `userDatabase`, etc. without flagging unrelated names like
   * `description`, `dbus`, `debit` (those embed `db` mid-token).
   */
  private _receiverLooksLikeDb(fullName: string): boolean {
    const lastDot = fullName.lastIndexOf('.');
    if (lastDot === -1) { return false; }
    const receiver = fullName.slice(0, lastDot);
    return this._tokensIntersectDbKeywords(receiver);
  }

  /**
   * §QW-2 — when the receiver of a SQL-shaped call (`x.query(...)`) is
   * narrowed by an enclosing `if (x instanceof T) { ... }` guard, treat the
   * receiver as DB-shaped if T tokenizes to a DB keyword. Lets us flag
   * `if (handle instanceof Pool) { handle.query(req.body.id); }` where the
   * receiver name alone wouldn't match.
   */
  private _receiverInstanceofImpliesDb(node: SyntaxNode, fullName: string, scope: SyntaxNode): boolean {
    const lastDot = fullName.lastIndexOf('.');
    if (lastDot === -1) { return false; }
    const receiver = fullName.slice(0, lastDot).replace(/\s*\(\s*\)\s*$/, '');
    const receiverSym = this._normalizeSymbol(receiver);
    if (!receiverSym) { return false; }
    const narrowings = this._findEnclosingInstanceofNarrowings(node, scope);
    const typeName = narrowings.get(receiverSym);
    if (!typeName) { return false; }
    return this._tokensIntersectDbKeywords(typeName);
  }

  private _tokensIntersectDbKeywords(text: string): boolean {
    const cleaned = text.replace(/\s*\(\s*\)\s*$/, '');
    const tokens = cleaned
      .split(/[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])/)
      .map(t => t.toLowerCase())
      .filter(Boolean);
    for (const t of tokens) {
      if (DB_RECEIVER_KEYWORDS.has(t)) { return true; }
    }
    return false;
  }

  /**
   * Heuristic: returns true if the first argument *contains* a string literal
   * (or template string) whose text starts with a SQL keyword. Handles bare
   * literals AND concatenations like `"SELECT … " + id` or `\`SELECT … ${id}\``.
   *
   * Conservative: requires a leading keyword on a word boundary so prose
   * containing the word "select" doesn't match.
   */
  private _firstArgIsSqlLiteral(node: SyntaxNode): boolean {
    const args = getCallArguments(node);
    if (args.length === 0) { return false; }
    const first = args[0];
    if (!first) { return false; }

    const SQL_KW = /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE|MERGE|TRUNCATE)\b/i;

    let matched = false;
    walkAst(first, (child) => {
      if (matched) { return false; }
      if (child.type === 'string' || child.type === 'string_literal' ||
          child.type === 'template_string' || child.type === 'string_fragment') {
        if (SQL_KW.test(child.text)) { matched = true; return false; }
      }
    });
    return matched;
  }
}
