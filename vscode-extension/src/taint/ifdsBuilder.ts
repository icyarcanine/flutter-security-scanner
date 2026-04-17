/**
 * Dart → CodeGraph builder for the IFDS taint engine.
 *
 * Uses web-tree-sitter via the existing ParserContext and the Dart grammar
 * already vendored by tree-sitter-dart. Produces statements in the shape the
 * IFDS solver consumes: each procedure is a linear CFG of Source / Assign /
 * Call / ReturnSite / Sanitize / Sink / Return / Exit.
 *
 * Scope: sufficient for the fixture tests (intra-procedural, inter-procedural
 * via direct same-file calls, and sanitizer recognition). Control flow beyond
 * sequential statements (if/for/while) is currently collapsed to sequential
 * successors — sufficient to prove the solver, but called out as a limitation.
 */

import {
  CodeGraph,
  EdgeKindTag,
  Loc,
  NodeKind,
  Procedure,
  Rhs,
  Statement,
} from '../models/graph';
import {
  childForFieldName,
  namedChild,
  namedChildCount,
  namedChildren,
  walkAst,
} from '../ast/traversal';
import { ParserContext } from '../ast/parser';
import { SemanticResolver } from '../ast/semanticResolver';

export interface BuilderConfig {
  /** Parameter names that are treated as taint sources when seen as formals. */
  sources: Set<string>;
  /** Call names treated as sinks; args at the call site are checked. */
  sinks: Map<string, string>; // call-name (last segment) -> sink kind label
  /** Call names treated as sanitizers; assigning their return kills the LHS. */
  sanitizers: Set<string>;
}

export const DEFAULT_BUILDER_CONFIG: BuilderConfig = {
  sources: new Set(['userInput', 'input', 'req', 'request', 'payload', 'data', 'body', 'query', 'params']),
  sinks: new Map<string, string>([
    ['rawQuery', 'sql'],
    ['query', 'sql'],
    ['execute', 'sql'],
    ['exec', 'command'],
    ['eval', 'code'],
    ['run', 'command'],
  ]),
  sanitizers: new Set(['sanitize', 'escape', 'escapeHtml', 'escapeSql', 'validate', 'encodeURIComponent']),
};

interface PendingProcedure {
  id: number;
  name: string;
  fileId: number;
  sigNode: any;
  bodyNode: any;
  params: Loc[];
  paramNames: string[];
  entry: number;
  exit: number;
  line: number;
}

let nextProcId = 0;

export class IfdsGraphBuilder {
  private readonly graph: CodeGraph;
  private readonly config: BuilderConfig;

  constructor(graph: CodeGraph, config: BuilderConfig = DEFAULT_BUILDER_CONFIG) {
    this.graph = graph;
    this.config = config;
  }

  /** Add a Dart file's parsed AST to the graph. Returns list of procedure IDs created. */
  public addDartFile(filePath: string, root: any): number[] {
    const fileId = this.graph.internFile(filePath);
    const pending: PendingProcedure[] = [];

    // Pass 1: discover every `function_signature` whose next named sibling is a
    // `function_body`. Also include methods inside class declarations.
    const signatures: any[] = [];
    walkAst(root, (n) => {
      if (n.type === 'function_signature' || n.type === 'method_signature') {
        signatures.push(n);
      }
    });

    for (const sigRaw of signatures) {
      // method_signature in Dart wraps an inner function_signature. Unwrap so
      // name / params come from the right place.
      const sig = sigRaw.type === 'method_signature'
        ? (findFirstChildOfType(sigRaw, 'function_signature') ?? sigRaw)
        : sigRaw;
      const body = findFunctionBody(sigRaw);
      if (!body) { continue; }
      const nameId = findFirstChildOfType(sig, 'identifier');
      const name = nameId?.text ?? '<anonymous>';
      const paramList = childForFieldName(sig, 'parameters')
        ?? findFirstChildOfType(sig, 'formal_parameter_list');
      const paramNames = paramList ? extractParamNames(paramList) : [];
      const procId = nextProcId++;
      const params: Loc[] = paramNames.map(n => ({ proc: procId, name: n }));
      const line = (sigRaw.startPosition?.row ?? 0) + 1;
      const entry = this.graph.addNode(NodeKind.EntryNode, fileId, toRange(sigRaw), line);
      const exit = this.graph.addNode(NodeKind.ExitNode, fileId, toRange(body), line);
      this.graph.statements.set(entry, { kind: 'entry', proc: procId, params });
      this.graph.statements.set(exit, { kind: 'exit', proc: procId });
      const proc: Procedure = { id: procId, name, entry, exit, params, fileId, line };
      this.graph.addProcedure(proc);
      pending.push({ id: procId, name, fileId, sigNode: sig, bodyNode: body, params, paramNames, entry, exit, line });
    }

    // Let the semantic resolver stitch together the global symbol table so
    // call-site resolution below benefits from it.
    const resolver = new SemanticResolver(this.graph);
    resolver.resolveWorkspace();

    // Pass 2: build body CFG per procedure.
    const procIds: number[] = [];
    for (const p of pending) {
      this.buildBody(p);
      procIds.push(p.id);
    }
    return procIds;
  }

  private buildBody(p: PendingProcedure): void {
    let prev = p.entry;

    // Source nodes for parameters whose names match our source set.
    for (const loc of p.params) {
      if (this.config.sources.has(loc.name)) {
        const nodeId = this.graph.addNode(NodeKind.Identifier, p.fileId, [0, 0], p.line);
        this.graph.statements.set(nodeId, { kind: 'source', lhs: loc, label: 'param:' + loc.name });
        this.graph.setProcedure(nodeId, p.id);
        this.graph.addEdge(prev, nodeId, EdgeKindTag.Cfg);
        prev = nodeId;
      }
    }

    // Walk the body and emit a real CFG with forks at if/else/while/for/try,
    // including loop back-edges, so branch-joining facts are correctly
    // merged at the merge point (the solver unions facts via the path-edge
    // set at each node).
    const block = findFirstChildOfType(p.bodyNode, 'block');
    if (block) {
      prev = this.emitBlock(p, prev, block);
    } else {
      // Arrow body: `=> expr` — treat as synthetic `return expr;`.
      const expr = this.findArrowExpression(p.bodyNode);
      if (expr) {
        prev = this.emitSyntheticReturn(p, prev, expr);
      }
    }

    // Link the last node to exit.
    this.graph.addEdge(prev, p.exit, EdgeKindTag.Cfg);
  }

  /** Emit a `block` as a sequence of statements; compound statements fork. */
  private emitBlock(p: PendingProcedure, prev: number, blockNode: any): number {
    for (let i = 0; i < namedChildCount(blockNode); i++) {
      const s = namedChild(blockNode, i);
      if (!s) { continue; }
      prev = this.emitOne(p, prev, s);
    }
    return prev;
  }

  private emitOne(p: PendingProcedure, prev: number, node: any): number {
    switch (node.type) {
      case 'block':
        return this.emitBlock(p, prev, node);
      case 'if_statement':
        return this.emitIf(p, prev, node);
      case 'while_statement':
        return this.emitWhile(p, prev, node);
      case 'do_statement':
        return this.emitDoWhile(p, prev, node);
      case 'for_statement':
        return this.emitFor(p, prev, node);
      case 'try_statement':
        return this.emitTry(p, prev, node);
      default:
        return this.emitStatement(p, prev, node);
    }
  }

  private emitIf(p: PendingProcedure, prev: number, ifNode: any): number {
    // Children: parenthesized_expression, block, [else_clause | block]
    const blocks: any[] = [];
    for (let i = 0; i < namedChildCount(ifNode); i++) {
      const k = namedChild(ifNode, i);
      if (!k) { continue; }
      if (k.type === 'block') { blocks.push(k); }
      else if (k.type === 'else_clause') {
        // else_clause wraps a block or another if_statement.
        for (let j = 0; j < namedChildCount(k); j++) {
          const ek = namedChild(k, j);
          if (ek && (ek.type === 'block' || ek.type === 'if_statement')) { blocks.push(ek); }
        }
      }
    }
    const merge = this.mkNoop(p, ifNode);
    if (blocks.length === 0) {
      this.graph.addEdge(prev, merge, EdgeKindTag.Cfg);
      return merge;
    }
    // Then
    const thenEnd = this.emitOne(p, prev, blocks[0]);
    this.graph.addEdge(thenEnd, merge, EdgeKindTag.Cfg);
    // Else (or implicit fall-through)
    if (blocks.length >= 2) {
      const elseEnd = this.emitOne(p, prev, blocks[1]);
      this.graph.addEdge(elseEnd, merge, EdgeKindTag.Cfg);
    } else {
      // No else: fall-through = prev directly to merge.
      this.graph.addEdge(prev, merge, EdgeKindTag.Cfg);
    }
    return merge;
  }

  private emitWhile(p: PendingProcedure, prev: number, node: any): number {
    const body = findFirstChildOfType(node, 'block');
    const header = this.mkNoop(p, node);
    this.graph.addEdge(prev, header, EdgeKindTag.Cfg);
    if (body) {
      const bodyEnd = this.emitBlock(p, header, body);
      this.graph.addEdge(bodyEnd, header, EdgeKindTag.Cfg); // loop back-edge
    }
    return header; // execution after loop exits from header (cond-false)
  }

  private emitDoWhile(p: PendingProcedure, prev: number, node: any): number {
    const body = findFirstChildOfType(node, 'block');
    if (!body) {
      const noop = this.mkNoop(p, node);
      this.graph.addEdge(prev, noop, EdgeKindTag.Cfg);
      return noop;
    }
    const bodyStart = this.mkNoop(p, node);
    this.graph.addEdge(prev, bodyStart, EdgeKindTag.Cfg);
    const bodyEnd = this.emitBlock(p, bodyStart, body);
    // Back-edge from bodyEnd to bodyStart (loop executes ≥1 times).
    this.graph.addEdge(bodyEnd, bodyStart, EdgeKindTag.Cfg);
    return bodyEnd;
  }

  private emitFor(p: PendingProcedure, prev: number, node: any): number {
    // Dart `for-in`: children include `inferred_type?`, `identifier (loopVar)`,
    // `identifier (collection)`, `block`. We model the loop-var as assigned
    // from the collection each iteration.
    const block = findFirstChildOfType(node, 'block');
    const header = this.mkNoop(p, node);
    this.graph.addEdge(prev, header, EdgeKindTag.Cfg);

    // Detect for-in: find the two identifier children (loop var + collection).
    const idents: any[] = [];
    for (let i = 0; i < namedChildCount(node); i++) {
      const k = namedChild(node, i);
      if (!k) { continue; }
      if (k.type === 'identifier') { idents.push(k); }
    }
    let cur = header;
    if (idents.length >= 2) {
      const loopVar: Loc = { proc: p.id, name: idents[0].text };
      const collection: Loc = { proc: p.id, name: idents[1].text };
      const assignId = this.graph.addNode(NodeKind.Assign, p.fileId, toRange(node), lineOf(node));
      this.graph.statements.set(assignId, { kind: 'assign', lhs: loopVar, rhs: { kind: 'var', loc: collection } });
      this.graph.setProcedure(assignId, p.id);
      this.graph.addEdge(header, assignId, EdgeKindTag.Cfg);
      cur = assignId;
    }

    if (block) {
      const bodyEnd = this.emitBlock(p, cur, block);
      this.graph.addEdge(bodyEnd, header, EdgeKindTag.Cfg); // back-edge
    } else {
      this.graph.addEdge(cur, header, EdgeKindTag.Cfg);
    }
    return header;
  }

  private emitTry(p: PendingProcedure, prev: number, node: any): number {
    // Flatten try/catch/finally into a chain: all blocks are potentially
    // reachable in sequence. Over-approximates but sound for taint.
    let cur = prev;
    for (let i = 0; i < namedChildCount(node); i++) {
      const k = namedChild(node, i);
      if (!k) { continue; }
      if (k.type === 'block') { cur = this.emitBlock(p, cur, k); }
      else if (k.type === 'catch_clause' || k.type === 'finally_clause' || k.type === 'on_part') {
        const inner = findFirstChildOfType(k, 'block');
        if (inner) { cur = this.emitBlock(p, cur, inner); }
      }
    }
    return cur;
  }

  /** Find the expression inside an arrow body (`=> expr`). */
  private findArrowExpression(bodyNode: any): any | null {
    for (let i = 0; i < namedChildCount(bodyNode); i++) {
      const c = namedChild(bodyNode, i);
      if (!c) { continue; }
      if (c.type === 'block') { continue; }
      return c;
    }
    return null;
  }

  private emitSyntheticReturn(p: PendingProcedure, prev: number, expr: any): number {
    // If the arrow expression is a call (e.g. `=> sanitize(x)`), handle it
    // via the call machinery with an implicit $ret LHS.
    const kids = expr.type === 'identifier' || expr.type === 'string_literal'
      ? [expr]
      : namedChildren(expr);
    const maybeCall = detectCallFromNodes([expr, ...kids]);
    const retLoc: Loc = { proc: p.id, name: '$ret' };
    if (maybeCall) {
      const callEnd = this.emitCallStmt(p, prev, expr, maybeCall, retLoc);
      const retId = this.graph.addNode(NodeKind.ReturnStmt, p.fileId, toRange(expr), lineOf(expr));
      this.graph.statements.set(retId, { kind: 'return', value: retLoc });
      this.graph.setProcedure(retId, p.id);
      this.graph.addEdge(callEnd, retId, EdgeKindTag.Cfg);
      return retId;
    }
    if (expr.type === 'identifier') {
      const loc: Loc = { proc: p.id, name: expr.text };
      const retId = this.graph.addNode(NodeKind.ReturnStmt, p.fileId, toRange(expr), lineOf(expr));
      this.graph.statements.set(retId, { kind: 'return', value: loc });
      this.graph.setProcedure(retId, p.id);
      this.graph.addEdge(prev, retId, EdgeKindTag.Cfg);
      return retId;
    }
    const rhs = this.rhsFrom(expr, p);
    const assignId = this.graph.addNode(NodeKind.Assign, p.fileId, toRange(expr), lineOf(expr));
    this.graph.statements.set(assignId, { kind: 'assign', lhs: retLoc, rhs });
    this.graph.setProcedure(assignId, p.id);
    this.graph.addEdge(prev, assignId, EdgeKindTag.Cfg);
    const retId = this.graph.addNode(NodeKind.ReturnStmt, p.fileId, toRange(expr), lineOf(expr));
    this.graph.statements.set(retId, { kind: 'return', value: retLoc });
    this.graph.setProcedure(retId, p.id);
    this.graph.addEdge(assignId, retId, EdgeKindTag.Cfg);
    return retId;
  }

  private emitStatement(p: PendingProcedure, prev: number, stmtNode: any): number {
    // Return
    if (stmtNode.type === 'return_statement') {
      const valExpr = firstNamedChildExcept(stmtNode, ['return']);
      if (!valExpr) {
        return this.link(p, prev, this.mkNoop(p, stmtNode));
      }
      // Synthesize a $ret Loc. If the expression is a bare identifier, use it
      // directly; otherwise emit an Assign($ret, <rhs>) then Return($ret).
      if (valExpr.type === 'identifier') {
        const loc: Loc = { proc: p.id, name: valExpr.text };
        const retId = this.graph.addNode(NodeKind.ReturnStmt, p.fileId, toRange(stmtNode), lineOf(stmtNode));
        this.graph.statements.set(retId, { kind: 'return', value: loc });
        this.graph.setProcedure(retId, p.id);
        this.graph.addEdge(prev, retId, EdgeKindTag.Cfg);
        return retId;
      }
      const retLoc: Loc = { proc: p.id, name: '$ret' };
      const rhs = this.rhsFrom(valExpr, p);
      const assignId = this.graph.addNode(NodeKind.Assign, p.fileId, toRange(stmtNode), lineOf(stmtNode));
      this.graph.statements.set(assignId, { kind: 'assign', lhs: retLoc, rhs });
      this.graph.setProcedure(assignId, p.id);
      this.graph.addEdge(prev, assignId, EdgeKindTag.Cfg);
      const retId = this.graph.addNode(NodeKind.ReturnStmt, p.fileId, toRange(stmtNode), lineOf(stmtNode));
      this.graph.statements.set(retId, { kind: 'return', value: retLoc });
      this.graph.setProcedure(retId, p.id);
      this.graph.addEdge(assignId, retId, EdgeKindTag.Cfg);
      return retId;
    }

    // Variable declaration with initializer: `local_variable_declaration`
    //   → `initialized_variable_definition` [ final_builtin? identifier RHS ]
    if (stmtNode.type === 'local_variable_declaration') {
      const def = findFirstChildOfType(stmtNode, 'initialized_variable_definition') ?? stmtNode;
      return this.emitInitializedVar(p, prev, def);
    }
    if (stmtNode.type === 'initialized_variable_definition') {
      return this.emitInitializedVar(p, prev, stmtNode);
    }

    // Assignment expression at statement top-level (uncommon; Dart typically
    // wraps assignments in expression_statement).
    if (stmtNode.type === 'assignment_expression') {
      const res = this.emitAssignmentExpression(p, prev, stmtNode, stmtNode);
      if (res !== null) { return res; }
    }

    // expression_statement: a call like `db.rawQuery(sql)` / `foo(bar)`,
    // possibly a sink, OR a bare assignment like `x = userInput;` /
    // `x = foo(y);`. Check assignment first — the Dart grammar wraps it as
    // `expression_statement > assignment_expression > assignable_expression
    // (identifier) , <rhs>`. Without this branch, bare assignments inside
    // blocks (e.g. inside if/else branches) get silently dropped, breaking
    // both taint propagation (then-branch writes) and strong-kill
    // (reassignment to a constant).
    if (stmtNode.type === 'expression_statement') {
      const assignExpr = findFirstChildOfType(stmtNode, 'assignment_expression');
      if (assignExpr) {
        const res = this.emitAssignmentExpression(p, prev, stmtNode, assignExpr);
        if (res !== null) { return res; }
      }
      const call = detectCall(stmtNode);
      if (call) {
        return this.emitCallStmt(p, prev, stmtNode, call, undefined);
      }
    }

    // Fallback: no-op.
    return this.link(p, prev, this.mkNoop(p, stmtNode));
  }

  private emitInitializedVar(p: PendingProcedure, prev: number, def: any): number {
    // Structure: [final_builtin?] identifier (name) then RHS sibling(s).
    const nameNode = findFirstChildOfType(def, 'identifier');
    if (!nameNode) {
      return this.link(p, prev, this.mkNoop(p, def));
    }
    const lhs: Loc = { proc: p.id, name: nameNode.text };
    // Everything after the first identifier makes up the RHS. Match by
    // positional index (tree-sitter creates fresh JS wrappers per access, so
    // reference equality with `indexOf` is unreliable).
    const kids = namedChildren(def);
    const nameIdx = kids.findIndex(k => sameNode(k, nameNode));
    const rhsNodes = nameIdx >= 0 ? kids.slice(nameIdx + 1) : kids;
    if (rhsNodes.length === 0) {
      return this.link(p, prev, this.mkNoop(p, def));
    }
    // Case: RHS is identifier + selector(argument_part) → a call.
    const call = detectCallFromNodes(rhsNodes);
    if (call) {
      return this.emitCallStmt(p, prev, def, call, lhs);
    }
    // Case: RHS is a string_literal with template_substitution or a bare
    // identifier — emit an Assign.
    const rhs = this.rhsFromNodes(rhsNodes, p);
    return this.emitAssignLikeRhs(p, prev, def, lhs, rhs);
  }

  private emitAssignLike(p: PendingProcedure, prev: number, srcNode: any, lhs: Loc, rhsExpr: any): number {
    const rhs = this.rhsFrom(rhsExpr, p);
    return this.emitAssignLikeRhs(p, prev, srcNode, lhs, rhs);
  }

  /**
   * Emit CFG for an `assignment_expression` node (LHS <op> RHS). Returns the
   * new prev node id, or null if the shape was not a simple scalar assign we
   * can model. Dart grammar: [assignable_expression (identifier) | identifier]
   * followed by the RHS expression. Compound LHS like `obj.field = ...` is
   * skipped (the scalar name is unchanged).
   */
  private emitAssignmentExpression(
    p: PendingProcedure,
    prev: number,
    srcNode: any,
    assignExpr: any,
  ): number | null {
    const kids = namedChildren(assignExpr);
    if (kids.length < 2) { return null; }
    const lhsNode = kids[0];
    const rhsNode = kids[1];
    // Compound LHS like `a.b = ...` or `a[i] = ...` — skip (we only model
    // scalar locals).
    if (lhsNode.type === 'assignable_expression' && namedChildCount(lhsNode) > 1) {
      return null;
    }
    const lhsIdent = lhsNode.type === 'identifier'
      ? lhsNode
      : findFirstChildOfType(lhsNode, 'identifier');
    if (!lhsIdent) { return null; }
    const lhs: Loc = { proc: p.id, name: lhsIdent.text };
    const call = detectCallFromNodes([rhsNode]);
    if (call) {
      return this.emitCallStmt(p, prev, srcNode, call, lhs);
    }
    return this.emitAssignLike(p, prev, srcNode, lhs, rhsNode);
  }

  private emitAssignLikeRhs(p: PendingProcedure, prev: number, srcNode: any, lhs: Loc, rhs: Rhs): number {
    const id = this.graph.addNode(NodeKind.Assign, p.fileId, toRange(srcNode), lineOf(srcNode));
    this.graph.statements.set(id, { kind: 'assign', lhs, rhs });
    this.graph.setProcedure(id, p.id);
    this.graph.addEdge(prev, id, EdgeKindTag.Cfg);
    return id;
  }

  private emitCallStmt(
    p: PendingProcedure,
    prev: number,
    srcNode: any,
    call: DetectedCall,
    lhs: Loc | undefined,
  ): number {
    const line = lineOf(srcNode);
    // Sanitizer: assign to lhs but kill any prior taint on lhs.
    if (lhs && this.config.sanitizers.has(call.lastName)) {
      const id = this.graph.addNode(NodeKind.Assign, p.fileId, toRange(srcNode), line);
      this.graph.statements.set(id, { kind: 'sanitize', lhs });
      this.graph.setProcedure(id, p.id);
      this.graph.addEdge(prev, id, EdgeKindTag.Cfg);
      return id;
    }

    // Sink: report if any argument is tainted at this node. Sinks fire
    // whether or not their result is assigned to a variable — `final rows =
    // db.rawQuery(userInput)` is still a SQL injection at the call site.
    const sinkKind = this.config.sinks.get(call.lastName);
    if (sinkKind) {
      const argLocs = call.args.map(a => this.exprReadLocs(a, p)).flat();
      const sinkId = this.graph.addNode(NodeKind.Call, p.fileId, toRange(srcNode), line);
      this.graph.statements.set(sinkId, {
        kind: 'sink',
        name: call.lastName,
        args: argLocs,
        line,
      });
      this.graph.setProcedure(sinkId, p.id);
      this.graph.addEdge(prev, sinkId, EdgeKindTag.Cfg);
      if (!lhs) { return sinkId; }
      // Sink's result assigned to a variable — conservatively treat the
      // result as untainted (we don't model DB-originated taint), and
      // explicitly clear any prior taint on LHS.
      const clearId = this.graph.addNode(NodeKind.Assign, p.fileId, toRange(srcNode), line);
      this.graph.statements.set(clearId, { kind: 'assign', lhs, rhs: { kind: 'const' } });
      this.graph.setProcedure(clearId, p.id);
      this.graph.addEdge(sinkId, clearId, EdgeKindTag.Cfg);
      return clearId;
    }

    // Regular call. If callee matches a local procedure by name, wire ICFG.
    const calleeProc = this.graph.procByName.get(call.lastName);
    const argLocs = call.args.map(a => this.exprSingleLoc(a, p)).filter(Boolean) as Loc[];
    const callId = this.graph.addNode(NodeKind.CallSite, p.fileId, toRange(srcNode), line);
    const retId = this.graph.addNode(NodeKind.ReturnSite, p.fileId, toRange(srcNode), line);
    this.graph.statements.set(callId, {
      kind: 'call',
      callee: call.lastName,
      calleeProc,
      args: argLocs,
      returnSite: retId,
    });
    this.graph.statements.set(retId, {
      kind: 'returnSite',
      callee: call.lastName,
      calleeProc,
      args: argLocs,
      ret: lhs,
    });
    this.graph.setProcedure(callId, p.id);
    this.graph.setProcedure(retId, p.id);
    this.graph.addEdge(prev, callId, EdgeKindTag.Cfg);
    this.graph.addEdge(callId, retId, EdgeKindTag.Cfg);
    if (calleeProc != null) {
      this.graph.recordCaller(calleeProc, callId);
      // Also record ICFG edges for human/debug introspection (not used by the
      // solver, which reaches the callee via path-edges from call-flow).
      const callee = this.graph.procedures.get(calleeProc);
      if (callee) {
        this.graph.addEdge(callId, callee.entry, EdgeKindTag.Icfg);
        this.graph.addEdge(callee.exit, retId, EdgeKindTag.IcfgReturn);
      }
    }
    return retId;
  }

  private mkNoop(p: PendingProcedure, srcNode: any): number {
    const id = this.graph.addNode(NodeKind.Unknown, p.fileId, toRange(srcNode), lineOf(srcNode));
    this.graph.statements.set(id, { kind: 'noop' });
    this.graph.setProcedure(id, p.id);
    return id;
  }

  private link(p: PendingProcedure, prev: number, cur: number): number {
    this.graph.addEdge(prev, cur, EdgeKindTag.Cfg);
    return cur;
  }

  // ── Expression → RHS / reads ─────────────────────────────────────────

  private rhsFrom(expr: any, p: PendingProcedure): Rhs {
    return this.rhsFromNodes([expr], p);
  }

  private rhsFromNodes(nodes: any[], p: PendingProcedure): Rhs {
    // Gather all identifier reads inside the expression(s). If exactly one,
    // treat as {kind:'var'}; if zero, {kind:'const'}; if multiple, 'compose'.
    const locs: Loc[] = [];
    for (const n of nodes) {
      this.collectIdentifierReads(n, p, locs);
    }
    if (locs.length === 0) { return { kind: 'const' }; }
    if (locs.length === 1) { return { kind: 'var', loc: locs[0] }; }
    // Deduplicate by name (same proc).
    const seen = new Set<string>();
    const unique: Loc[] = [];
    for (const l of locs) {
      const k = `${l.proc}::${l.name}`;
      if (!seen.has(k)) { seen.add(k); unique.push(l); }
    }
    return { kind: 'compose', parts: unique };
  }

  /**
   * Collect identifier reads from an expression node. String interpolation
   * (`template_substitution`) contributes its inner identifier. A bare
   * identifier contributes itself. Calls contribute their arguments only.
   */
  private collectIdentifierReads(n: any, p: PendingProcedure, out: Loc[]): void {
    if (!n) { return; }
    // template_substitution in Dart strings: the substring looks like `$foo`
    // or `${foo.bar}`. The identifier shows up as a child or as .text minus
    // the dollar prefix. We walk descendants to pick up any identifier.
    if (n.type === 'template_substitution' || n.type === 'string_literal') {
      // Walk descendants for identifier nodes.
      walkAst(n, (child) => {
        if (child === n) { return; }
        if (child.type === 'identifier' || child.type === 'identifier_dollar_escaped') {
          // Skip identifiers that are method names inside a selector.
          if (child.parent && child.parent.type === 'unconditional_assignable_selector') { return; }
          out.push({ proc: p.id, name: child.text });
          return false;
        }
      });
      return;
    }
    if (n.type === 'identifier' || n.type === 'identifier_dollar_escaped') {
      out.push({ proc: p.id, name: n.text });
      return;
    }
    if (n.type === 'selector') {
      // `(x)` → argument part containing identifiers we want to collect.
      walkAst(n, (child) => {
        if (child === n) { return; }
        if (child.type === 'identifier') { out.push({ proc: p.id, name: child.text }); return false; }
      });
      return;
    }
    // Fallback: walk descendants.
    for (let i = 0; i < namedChildCount(n); i++) {
      this.collectIdentifierReads(namedChild(n, i), p, out);
    }
  }

  /** Single-loc read for a call-argument expression (picks the first identifier). */
  private exprSingleLoc(expr: any, p: PendingProcedure): Loc | null {
    const reads: Loc[] = [];
    this.collectIdentifierReads(expr, p, reads);
    return reads[0] ?? null;
  }

  /** All locs read by an argument expression (used for sink arg checking). */
  private exprReadLocs(expr: any, p: PendingProcedure): Loc[] {
    const reads: Loc[] = [];
    this.collectIdentifierReads(expr, p, reads);
    return reads;
  }
}

// ── Tree-sitter helpers ───────────────────────────────────────────────

interface DetectedCall {
  /** Full dotted callee name, e.g. "db.rawQuery". */
  fullName: string;
  /** Last segment, e.g. "rawQuery". */
  lastName: string;
  /** Argument AST nodes. */
  args: any[];
}

function findFunctionBody(sig: any): any | null {
  // The body is typically the next *named* sibling after the signature.
  if (sig.nextNamedSibling && sig.nextNamedSibling.type === 'function_body') {
    return sig.nextNamedSibling;
  }
  // Fallback: search within the parent for a sibling body.
  const parent = sig.parent;
  if (!parent) { return null; }
  const kids = namedChildren(parent);
  const idx = kids.indexOf(sig);
  if (idx >= 0 && idx + 1 < kids.length && kids[idx + 1].type === 'function_body') {
    return kids[idx + 1];
  }
  return null;
}

function findFirstChildOfType(n: any, type: string): any | null {
  if (!n) { return null; }
  for (let i = 0; i < namedChildCount(n); i++) {
    const c = namedChild(n, i);
    if (c && c.type === type) { return c; }
  }
  return null;
}

function firstNamedChildExcept(n: any, excluded: string[]): any | null {
  for (let i = 0; i < namedChildCount(n); i++) {
    const c = namedChild(n, i);
    if (c && !excluded.includes(c.type)) { return c; }
  }
  return null;
}

function extractParamNames(paramList: any): string[] {
  const names: string[] = [];
  for (let i = 0; i < namedChildCount(paramList); i++) {
    const p = namedChild(paramList, i);
    if (!p) { continue; }
    // The parameter's identifier is the last `identifier` descendant (after any
    // type_identifier).
    let lastIdent: any = null;
    walkAst(p, (child) => {
      if (child.type === 'identifier' && child.parent?.type !== 'type_identifier') {
        lastIdent = child;
      }
    });
    if (lastIdent) { names.push(lastIdent.text); }
  }
  return names;
}

function lineOf(node: any): number {
  return (node.startPosition?.row ?? 0) + 1;
}

/** Tree-sitter JS wrappers are not reference-stable. Compare by position. */
function sameNode(a: any, b: any): boolean {
  if (!a || !b) { return false; }
  if (a === b) { return true; }
  return a.startIndex === b.startIndex && a.endIndex === b.endIndex && a.type === b.type;
}

function toRange(node: any): [number, number] {
  return [node.startIndex ?? 0, node.endIndex ?? 0];
}

/**
 * Detect a call in an expression_statement like `db.rawQuery(sql);` or
 * `foo(bar);`. Returns the dotted name and argument nodes, or null.
 */
function detectCall(exprStmt: any): DetectedCall | null {
  const kids = namedChildren(exprStmt);
  return detectCallFromNodes(kids);
}

function detectCallFromNodes(kids: any[]): DetectedCall | null {
  // Signature: identifier (selector)* selector-with-argument_part
  // For `db.rawQuery(sql)`: [identifier "db", selector ".rawQuery", selector "(sql)"]
  // For `foo(bar)`:        [identifier "foo", selector "(bar)"]
  if (kids.length === 0) { return null; }
  let argPart: any | null = null;
  let argSelectorIdx = -1;
  for (let i = 0; i < kids.length; i++) {
    const k = kids[i];
    if (k.type === 'selector') {
      const ap = findFirstChildOfType(k, 'argument_part');
      if (ap) { argPart = ap; argSelectorIdx = i; break; }
    }
    if (k.type === 'argument_part') { argPart = k; argSelectorIdx = i; break; }
  }
  if (!argPart) { return null; }
  // Collect dotted name from identifier + selector chain up to the arg selector.
  const nameParts: string[] = [];
  for (let i = 0; i < argSelectorIdx; i++) {
    const k = kids[i];
    if (k.type === 'identifier') {
      nameParts.push(k.text);
      continue;
    }
    if (k.type === 'selector') {
      const uas = findFirstChildOfType(k, 'unconditional_assignable_selector');
      if (uas) {
        const ident = findFirstChildOfType(uas, 'identifier');
        if (ident) { nameParts.push(ident.text); continue; }
      }
      const ident = findFirstChildOfType(k, 'identifier');
      if (ident) { nameParts.push(ident.text); }
    }
  }
  if (nameParts.length === 0) { return null; }
  const argsContainer = findFirstChildOfType(argPart, 'arguments') ?? argPart;
  const args: any[] = [];
  for (let i = 0; i < namedChildCount(argsContainer); i++) {
    const a = namedChild(argsContainer, i);
    if (!a) { continue; }
    // argument wraps the actual expression in some grammars; unwrap.
    if (a.type === 'argument') {
      const inner = namedChild(a, 0);
      if (inner) { args.push(inner); continue; }
    }
    args.push(a);
  }
  return {
    fullName: nameParts.join('.'),
    lastName: nameParts[nameParts.length - 1],
    args,
  };
}

/** For callers that want to re-probe expression identifier reads. */
export function _collectIdentifiers(n: any): string[] {
  const out: string[] = [];
  walkAst(n, (child) => {
    if (child.type === 'identifier') { out.push(child.text); }
  });
  return out;
}
