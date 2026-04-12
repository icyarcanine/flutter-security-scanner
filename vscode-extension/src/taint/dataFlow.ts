import type { SyntaxNode } from 'web-tree-sitter';
import {
  children,
  childForFieldName,
  findNodesByType,
  getAssignmentNames,
  getAssignmentValue,
  getCallArguments,
  getCallName,
  getFunctionParameterNames,
  isAssignment,
  isFunctionCall,
  namedChild,
  namedChildCount,
  walkAst,
} from '../ast/traversal';

export type SinkKind = 'sql' | 'command' | 'code' | 'html';

export interface TaintFinding {
  node: SyntaxNode;
  sinkName: string;
  sinkKind: SinkKind;
  isSanitized: boolean;
  /** True when taint arrived via an indirect path (weakTainted) — caller may downgrade severity. */
  isIndirect: boolean;
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

interface ScopeState {
  /** Directly tainted: from sources or short alias chains (depth ≤ MAX_TAINT_DEPTH). */
  tainted: Set<string>;
  /**
   * Weakly tainted: indirect sources only — Object.assign mutations, alias chains that
   * exceed MAX_TAINT_DEPTH, and function-summary propagation.  Exact-symbol match only;
   * NOT propagated through property-access children (e.g. weakTainted `config` does NOT
   * make `config.timeout` tainted).
   */
  weakTainted: Set<string>;
  sanitized: Set<string>;
  dynamicSql: Set<string>;
  /** Depth of alias chain for each tainted variable (direct source = 0). */
  taintDepth: Map<string, number>;
  /** Function-level summaries: funcName → parameter indices whose value flows to return. */
  summaries: Map<string, number[]>;
}

/** Maximum alias-chain depth before taint degrades to weakTainted. */
const MAX_TAINT_DEPTH = 3;

const SOURCE_PARAMETER_NAMES = new Set(['input', 'userInput', 'data', 'payload', 'req', 'request']);
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

const SANITIZER_NAME_PATTERN =
  /(?:^|\.)(sanitize|escape|escapeHtml|escapeSql|escapeShell|shellEscape|sqlstring\.escape|dompurify\.sanitize|encodeURI|encodeURIComponent|encodeHTML|clean|normalize|validator\.escape)$/i;
const VALIDATION_NAME_PATTERN =
  /(?:^|\.)(validate|validated|assertValid|assertSafe|ensureValid|ensureSafe|checkValid|checkSafe|isAllowed|schema\.parse|safeParse|parseInt|parseFloat)$/i;

/**
 * Intra-procedural taint tracker for high-confidence source-to-sink findings.
 * It deliberately avoids inter-file and inter-procedural guesses to keep noise low.
 */
export class IntraProceduralTaintTracker {
  public findTaintedSinks(root: SyntaxNode, lang: string): TaintFinding[] {
    const summaries = this._buildSummaries(root);
    const findings: TaintFinding[] = [];
    for (const scope of this._scopes(root)) {
      const state = this._seedScope(scope, summaries);

      walkAst(scope, (node) => {
        if (node !== scope && FUNCTION_SCOPE_TYPES.includes(node.type)) {
          return false;
        }

        if (isFunctionCall(node)) {
          this._recordValidationCall(node, state);
          this._propagateObjectMutation(node, state);
          const sink = this._sinkForCall(node);
          if (sink) {
            const isSanitized = this._isSanitizedSinkCall(node, sink, state);
            if (!isSanitized && this._callReceivesTaint(node, sink, state)) {
              const isIndirect = !this._callReceivesStrongTaint(node, sink, state);
              findings.push({ node, sinkName: sink.name, sinkKind: sink.kind, isSanitized: false, isIndirect });
            } else if (isSanitized && this._callReceivesTaint(node, sink, state)) {
              findings.push({ node, sinkName: sink.name, sinkKind: sink.kind, isSanitized: true, isIndirect: false });
            }
          }
        }

        if (isAssignment(node)) {
          const assignmentSink = this._sinkForAssignment(node);
          if (assignmentSink && this._assignmentReceivesTaint(node, state)) {
            findings.push({
              node,
              sinkName: assignmentSink.name,
              sinkKind: assignmentSink.kind,
              isSanitized: this._isSanitizedExpression(getAssignmentValue(node), state),
              isIndirect: !this._assignmentReceivesStrongTaint(node, state),
            });
          }

          this._propagateAssignment(node, lang, state);
        }
      });
    }
    return findings;
  }

  public findDynamicAstSinks(root: SyntaxNode, lang: string): AstSinkFinding[] {
    const summaries = this._buildSummaries(root);
    const findings: AstSinkFinding[] = [];
    for (const scope of this._scopes(root)) {
      const state = this._seedScope(scope, summaries);

      walkAst(scope, (node) => {
        if (node !== scope && FUNCTION_SCOPE_TYPES.includes(node.type)) {
          return false;
        }

        if (isFunctionCall(node)) {
          this._recordValidationCall(node, state);
          this._propagateObjectMutation(node, state);
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
    }
    return findings;
  }

  private _scopes(root: SyntaxNode): SyntaxNode[] {
    const scopes = findNodesByType(root, FUNCTION_SCOPE_TYPES);
    return scopes.length > 0 ? scopes : [root];
  }

  private _seedScope(scope: SyntaxNode, summaries: Map<string, number[]>): ScopeState {
    const tainted = new Set<string>();
    const taintDepth = new Map<string, number>();
    for (const name of getFunctionParameterNames(scope)) {
      if (SOURCE_PARAMETER_NAMES.has(name)) {
        tainted.add(name);
        taintDepth.set(name, 0);
      }
    }
    return {
      tainted,
      weakTainted: new Set<string>(),
      sanitized: new Set<string>(),
      dynamicSql: new Set<string>(),
      taintDepth,
      summaries,
    };
  }

  // ─── Fix 2: clear taint on clean reassignment, preserve on augmented ─────────

  private _propagateAssignment(node: SyntaxNode, lang: string, state: ScopeState): void {
    const targets = getAssignmentNames(node, lang)
      .map(name => this._normalizeSymbol(name))
      .filter((name): name is string => name != null);
    if (targets.length === 0) { return; }

    const value = getAssignmentValue(node);
    const isSanitized = this._isSanitizedExpression(value, state);
    const isTainted = value != null && this._isExpressionTainted(value, state);
    const isDynamicSql = value != null && this._isDynamicSqlExpressionWithState(value, state);
    // Fix 2: augmented assignments (+=, -=, …) never clear existing taint.
    const isAugmented = this._isAugmentedAssignment(node);

    for (const target of targets) {
      if (isTainted && !isSanitized) {
        // Fix 5: compute propagation depth; exceed MAX → weakTainted.
        const sourceDepth = this._getExpressionDepth(value!, state);
        const newDepth = sourceDepth + 1;

        if (newDepth > MAX_TAINT_DEPTH) {
          // Fix 1+5: exceeded depth limit — degrade to weakTainted.
          state.weakTainted.add(target);
          state.tainted.delete(target);
        } else {
          state.tainted.add(target);
          state.weakTainted.delete(target);
        }
        state.taintDepth.set(target, newDepth);
        state.sanitized.delete(target);
      } else if (isSanitized) {
        state.tainted.delete(target);
        state.weakTainted.delete(target);
        state.taintDepth.delete(target);
        state.sanitized.add(target);
      } else if (!isAugmented) {
        // Fix 2: only clear taint for non-augmented (plain `=`) assignments.
        state.tainted.delete(target);
        state.weakTainted.delete(target);
        state.taintDepth.delete(target);
        state.sanitized.delete(target);
      }
      // For augmented assignments with a clean RHS: existing taint is preserved as-is.

      if (isDynamicSql && !isSanitized) {
        state.dynamicSql.add(target);
      } else if (!isAugmented) {
        state.dynamicSql.delete(target);
      }
    }
  }

  // ─── Fix 2 helper: detect augmented-assignment operators (+=, -= …) ──────────

  private _isAugmentedAssignment(node: SyntaxNode): boolean {
    // Python uses a distinct node type.
    if (node.type === 'augmented_assignment') { return true; }
    if (!['assignment_expression', 'assignment'].includes(node.type)) { return false; }
    // JS/TS: assignment_expression, operator is an unnamed child like '+='.
    for (const child of children(node)) {
      const t = child.text ?? '';
      if (t.length > 1 && t.endsWith('=') && t !== '==' && t !== '!=' && t !== '<=' && t !== '>=') {
        return true;
      }
    }
    return false;
  }

  // ─── Fix 5 helper: depth of taint in an expression ───────────────────────────

  private _getExpressionDepth(node: SyntaxNode, state: ScopeState): number {
    if (this._isDirectSourceExpression(node)) { return 0; }
    const symbol = this._normalizeSymbol(node.text);
    if (symbol) {
      return state.taintDepth.get(symbol) ?? 0;
    }
    let maxDepth = 0;
    for (let i = 0; i < namedChildCount(node); i++) {
      const child = namedChild(node, i);
      if (child && this._isExpressionTainted(child, state)) {
        const d = this._getExpressionDepth(child, state);
        if (d > maxDepth) { maxDepth = d; }
      }
    }
    return maxDepth;
  }

  // ─── Fix 3: build function-return summaries ───────────────────────────────────

  /**
   * One-pass scan: for every function that has a bare `return <param>;` statement
   * record which parameter indices flow directly to the return value.
   */
  private _buildSummaries(root: SyntaxNode): Map<string, number[]> {
    const summaries = new Map<string, number[]>();

    walkAst(root, (node) => {
      if (!FUNCTION_SCOPE_TYPES.includes(node.type)) { return; }

      const nameNode = childForFieldName(node, 'name');
      const funcName = nameNode?.text?.trim();
      if (!funcName) { return; }

      const params = getFunctionParameterNames(node);
      if (params.length === 0) { return; }

      const returnParamIndices: number[] = [];

      walkAst(node, (inner) => {
        // Don't cross nested function boundaries.
        if (inner !== node && FUNCTION_SCOPE_TYPES.includes(inner.type)) { return false; }
        if (inner.type === 'return_statement') {
          const retVal = namedChild(inner, 0);
          if (retVal && retVal.type === 'identifier') {
            const idx = params.indexOf(retVal.text);
            if (idx >= 0 && !returnParamIndices.includes(idx)) {
              returnParamIndices.push(idx);
            }
          }
        }
      });

      if (returnParamIndices.length > 0) {
        summaries.set(funcName, returnParamIndices);
      }
    });

    return summaries;
  }

  private _recordValidationCall(node: SyntaxNode, state: ScopeState): void {
    const name = getCallName(node);
    if (!VALIDATION_NAME_PATTERN.test(name)) { return; }

    for (const arg of getCallArguments(node)) {
      if (!this._isExpressionTainted(arg, state)) { continue; }
      this._markSanitized(arg, state);
    }
  }

  // ─── Fix 1: Object.assign → weakTainted only ─────────────────────────────────

  /**
   * Detects `Object.assign(target, src, …)` where any source is tainted.
   * Adds `target` to weakTainted (not tainted) so property accesses like
   * `target.timeout` are not considered tainted (Fix 4 noise reduction).
   */
  private _propagateObjectMutation(node: SyntaxNode, state: ScopeState): void {
    if (getCallName(node) !== 'Object.assign') { return; }
    const args = getCallArguments(node);
    if (args.length < 2) { return; }

    const sourcesTainted = args.slice(1).some(arg => this._isExpressionTainted(arg, state));
    if (!sourcesTainted) { return; }

    const targetSymbol = this._normalizeSymbol(args[0].text);
    if (!targetSymbol) { return; }

    // Only assign to weakTainted; preserve any existing strong taint.
    if (!state.tainted.has(targetSymbol) && !state.sanitized.has(targetSymbol)) {
      state.weakTainted.add(targetSymbol);
      if (!state.taintDepth.has(targetSymbol)) {
        state.taintDepth.set(targetSymbol, MAX_TAINT_DEPTH);
      }
    }
  }

  private _callReceivesTaint(node: SyntaxNode, sink: SinkDefinition, state: ScopeState): boolean {
    const args = getCallArguments(node);
    if (sink.kind === 'sql') {
      const first = args[0];
      return first != null && this._isExpressionTainted(first, state) ||
        args.some(arg => this._isExpressionTainted(arg, state)) && !this._isParameterizedSqlCall(node, sink, state);
    }
    return args.some(arg => this._isExpressionTainted(arg, state));
  }

  /** Same as _callReceivesTaint but ignores weakTainted — used to set isIndirect. */
  private _callReceivesStrongTaint(node: SyntaxNode, sink: SinkDefinition, state: ScopeState): boolean {
    const args = getCallArguments(node);
    if (sink.kind === 'sql') {
      const first = args[0];
      return first != null && this._isExpressionStronglyTainted(first, state) ||
        args.some(arg => this._isExpressionStronglyTainted(arg, state)) && !this._isParameterizedSqlCall(node, sink, state);
    }
    return args.some(arg => this._isExpressionStronglyTainted(arg, state));
  }

  private _assignmentReceivesTaint(node: SyntaxNode, state: ScopeState): boolean {
    const value = getAssignmentValue(node);
    return value != null && this._isExpressionTainted(value, state);
  }

  private _assignmentReceivesStrongTaint(node: SyntaxNode, state: ScopeState): boolean {
    const value = getAssignmentValue(node);
    return value != null && this._isExpressionStronglyTainted(value, state);
  }

  // ─── Fix 1+3+4: taint check with weakTainted exact-only semantics ─────────────

  /**
   * Returns true if the expression carries taint (strong or weak).
   * weakTainted is checked for EXACT symbol matches only — it is NOT propagated
   * through recursive child descent, preventing `config.timeout` from being
   * considered tainted when only `config` is weakTainted (Fix 4).
   */
  private _isExpressionTainted(node: SyntaxNode | null, state: ScopeState): boolean {
    if (!node) { return false; }
    const symbol = this._normalizeSymbol(node.text);
    if (symbol && state.sanitized.has(symbol)) { return false; }
    if (symbol && state.tainted.has(symbol)) { return true; }
    // Fix 1/4: weakTainted only matches the exact symbol, not via child descent.
    if (symbol && state.weakTainted.has(symbol)) { return true; }
    if (this._isDirectSourceExpression(node)) { return true; }
    if (this._isSanitizedExpression(node, state)) { return false; }

    // Fix 3: check function-return summaries.
    if (isFunctionCall(node)) {
      const callName = getCallName(node);
      const paramIndices = state.summaries.get(callName);
      if (paramIndices) {
        const callArgs = getCallArguments(node);
        for (const idx of paramIndices) {
          if (callArgs[idx] && this._isExpressionTainted(callArgs[idx], state)) { return true; }
        }
      }
    }

    // Recursive descent uses strong-only check to avoid propagating weakTainted
    // through property-access chains (Fix 4).
    for (let i = 0; i < namedChildCount(node); i++) {
      const child = namedChild(node, i);
      if (child && this._isExpressionStronglyTainted(child, state)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Like _isExpressionTainted but only checks the strong `tainted` set — ignores
   * weakTainted.  Used for recursive descent and for determining `isIndirect`.
   */
  private _isExpressionStronglyTainted(node: SyntaxNode | null, state: ScopeState): boolean {
    if (!node) { return false; }
    const symbol = this._normalizeSymbol(node.text);
    if (symbol && state.sanitized.has(symbol)) { return false; }
    if (symbol && state.tainted.has(symbol)) { return true; }
    if (this._isDirectSourceExpression(node)) { return true; }
    if (this._isSanitizedExpression(node, state)) { return false; }

    // Fix 3: summaries contribute to strong taint too.
    if (isFunctionCall(node)) {
      const callName = getCallName(node);
      const paramIndices = state.summaries.get(callName);
      if (paramIndices) {
        const callArgs = getCallArguments(node);
        for (const idx of paramIndices) {
          if (callArgs[idx] && this._isExpressionStronglyTainted(callArgs[idx], state)) { return true; }
        }
      }
    }

    for (let i = 0; i < namedChildCount(node); i++) {
      const child = namedChild(node, i);
      if (child && this._isExpressionStronglyTainted(child, state)) {
        return true;
      }
    }
    return false;
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
    const compact = node.text.replace(/\s+/g, '');
    if (/^(?:req|request)\.(?:body|query|params)(?:\.|\[|$)/.test(compact)) {
      return true;
    }
    if (/^(?:req|request)\.(?:uri\.queryparameters|queryparameters|headers|cookies)(?:\.|\[|$)/i.test(compact)) {
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

  private _sinkForCall(node: SyntaxNode): SinkDefinition | null {
    const fullName = getCallName(node);
    const bareName = fullName.split('.').pop() ?? fullName;
    const lowerFull = fullName.toLowerCase();
    const lowerBare = bareName.toLowerCase();

    if (['query', 'execute', 'executequery', 'raw', 'rawquery'].includes(lowerBare)) {
      return { name: fullName, kind: 'sql' };
    }

    if (['exec', 'execsync', 'execfile', 'spawn', 'system', 'popen'].includes(lowerBare) ||
      lowerFull === 'os.system' ||
      lowerFull === 'process.run' ||
      lowerFull === 'process.start') {
      return { name: fullName, kind: 'command' };
    }

    if (fullName === 'eval' || fullName === 'Function' || lowerBare === 'eval') {
      return { name: fullName, kind: 'code' };
    }

    if (lowerFull === 'document.write') {
      return { name: fullName, kind: 'html' };
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
        return this._isDynamicSqlExpressionWithState(args[0], state);
      case 'command':
        return this._isDynamicExpression(args[0], state);
      case 'code':
        return true;
      case 'html':
        return args.some(arg => this._isDynamicExpression(arg, state));
    }
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
