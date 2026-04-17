/**
 * IFDS (Reps–Horwitz–Sagiv) solver for taint analysis.
 *
 * Domain:
 *   Facts D = {Λ (zero-fact)} ∪ {abstract Locs}
 *
 * Path-edges:
 *   (sp, d1) → (n, d2)  means: if procedure p of n has entry sp and we start
 *   with d1 holding at sp, then d2 holds at n.
 *
 * Summaries:
 *   Summary(sp, d1) = { d2 | (sp, d1) → (exit_p, d2) }  cached per entry-fact
 *   and reused at every call site that induces the same entry fact, exactly
 *   per the tabulation algorithm.
 *
 * Flow functions are per-statement. See applyFlow().
 */

import {
  CodeGraph,
  EdgeKindTag,
  Loc,
  locEq,
  locKey,
  Procedure,
  Rhs,
  Statement,
} from '../models/graph';

/** Abstract fact: either the zero-fact (Λ) or a specific Loc. */
export type Fact = { kind: 'zero' } | { kind: 'loc'; loc: Loc };
const ZERO: Fact = { kind: 'zero' };

function factKey(f: Fact): string {
  return f.kind === 'zero' ? 'Λ' : locKey(f.loc);
}

function factEq(a: Fact, b: Fact): boolean {
  if (a.kind !== b.kind) { return false; }
  if (a.kind === 'zero') { return true; }
  return locEq(a.loc, (b as { kind: 'loc'; loc: Loc }).loc);
}

function pathEdgeKey(sp: number, d1: Fact, n: number, d2: Fact): string {
  return `${sp}|${factKey(d1)}|${n}|${factKey(d2)}`;
}

function summaryKey(sp: number, d1: Fact): string {
  return `${sp}|${factKey(d1)}`;
}

interface PathEdge {
  sp: number;   // entry node of owning procedure
  d1: Fact;     // entry fact
  n: number;    // current node
  d2: Fact;     // fact at n
}

/** A reachability result: fact f holds at node n. */
export interface Reachability {
  node: number;
  fact: Fact;
}

export class IfdsSolver {
  private readonly graph: CodeGraph;
  private worklist: PathEdge[] = [];
  private readonly pathEdges = new Set<string>();
  /** sp|d1 → set of d2 at exit (summary edges). */
  private readonly summaries = new Map<string, Set<string>>();
  /** sp|d1 → actual Fact objects indexed by factKey (for mapping back). */
  private readonly summaryFacts = new Map<string, Map<string, Fact>>();
  /** Call sites whose callee tabulation is pending under a given (sp, d1). */
  private readonly pendingCallers = new Map<string, { callSite: number; callerSp: number; callerD1: Fact; callerD2: Fact }[]>();
  /** Cached result of collectReachable() after solve() completes. */
  private reachCache: Reachability[] | null = null;
  /** Cached return-loc sets per procedure id. */
  private readonly returnLocCache = new Map<number, Loc[]>();

  constructor(graph: CodeGraph) {
    this.graph = graph;
  }

  /**
   * Run tabulation. Seeds every procedure entry with the zero-fact so that
   * sources discovered inside a procedure propagate under Λ, and additional
   * entry facts are discovered at call-sites.
   */
  public solve(): Reachability[] {
    for (const proc of this.graph.procedures.values()) {
      this.propagate({ sp: proc.entry, d1: ZERO, n: proc.entry, d2: ZERO });
    }

    while (this.worklist.length > 0) {
      const edge = this.worklist.pop()!;
      this.step(edge);
    }

    this.reachCache = this.collectReachable();
    return this.reachCache;
  }

  private propagate(e: PathEdge): void {
    const key = pathEdgeKey(e.sp, e.d1, e.n, e.d2);
    if (this.pathEdges.has(key)) { return; }
    this.pathEdges.add(key);
    this.worklist.push(e);
  }

  private step(e: PathEdge): void {
    const stmt = this.graph.statements.get(e.n);
    const proc = this.ownerProc(e.n);
    if (!proc) { return; }

    // If we reached the exit node of our procedure, update summary and
    // propagate through any pending callers.
    if (stmt?.kind === 'exit') {
      this.recordSummary(e.sp, e.d1, e.d2);
      this.applyPendingCallers(e.sp, e.d1, e.d2);
      return;
    }

    // If this node is a call-site, handle call flow (to callee entry) AND
    // call-to-return flow (intra-procedural shortcut for facts unrelated to
    // the call), then wait for the callee's summary to propagate to the
    // return-site.
    if (stmt?.kind === 'call') {
      this.handleCall(e, stmt);
      return;
    }

    // Normal intra-procedural CFG step: for each CFG successor m, apply the
    // flow function on e.d2 and propagate the resulting facts at m.
    const successors = this.graph.outEdges(e.n, EdgeKindTag.Cfg);
    for (const succ of successors) {
      const mStmt = this.graph.statements.get(succ.dst);
      for (const d3 of this.applyFlow(stmt, mStmt, e.d2, proc)) {
        this.propagate({ sp: e.sp, d1: e.d1, n: succ.dst, d2: d3 });
      }
    }
  }

  /** Call-site handling: call-flow to callee entry + call-to-return shortcut. */
  private handleCall(
    e: PathEdge,
    call: Extract<Statement, { kind: 'call' }>,
  ): void {
    const returnSite = call.returnSite;
    const retStmt = this.graph.statements.get(returnSite) as
      | Extract<Statement, { kind: 'returnSite' }>
      | undefined;

    // Call-to-return (intra-proc shortcut): facts unrelated to the call's
    // actuals flow straight through. Facts equal to an actual are killed —
    // their flow must go through the callee.
    for (const d3 of this.callToReturn(e.d2, call.args)) {
      this.propagate({ sp: e.sp, d1: e.d1, n: returnSite, d2: d3 });
    }

    if (call.calleeProc == null) {
      // Unknown callee: conservatively, taint on actuals can't propagate
      // through the call. The call-to-return shortcut above keeps everything
      // else flowing. (A real engine would also have a library-summary table
      // here; we only need the fixture-defined intra-repo calls.)
      return;
    }

    const callee = this.graph.procedures.get(call.calleeProc);
    if (!callee) { return; }

    // Call flow: map actuals to formals, map zero-fact to zero-fact.
    const entryFacts = this.callFlow(e.d2, call.args, callee);

    for (const d3 of entryFacts) {
      // Register this call-site as interested in the callee tabulation under
      // entry fact d3 so that when summaries are produced we can propagate
      // them back to this call-site's return-site.
      const pendKey = summaryKey(callee.entry, d3);
      const list = this.pendingCallers.get(pendKey) ?? [];
      list.push({ callSite: e.n, callerSp: e.sp, callerD1: e.d1, callerD2: e.d2 });
      this.pendingCallers.set(pendKey, list);

      // Kick off callee tabulation under d3.
      this.propagate({ sp: callee.entry, d1: d3, n: callee.entry, d2: d3 });

      // If summaries already exist for (callee.entry, d3), propagate back now.
      const existing = this.summariesFor(callee.entry, d3);
      for (const exitFact of existing) {
        for (const d5 of this.returnFlow(exitFact, call, retStmt, callee)) {
          this.propagate({ sp: e.sp, d1: e.d1, n: returnSite, d2: d5 });
        }
      }
    }
  }

  private recordSummary(sp: number, d1: Fact, d2: Fact): void {
    const k = summaryKey(sp, d1);
    let set = this.summaries.get(k);
    if (!set) { set = new Set(); this.summaries.set(k, set); }
    const df = factKey(d2);
    if (set.has(df)) { return; }
    set.add(df);
    let facts = this.summaryFacts.get(k);
    if (!facts) { facts = new Map(); this.summaryFacts.set(k, facts); }
    facts.set(df, d2);
  }

  private summariesFor(sp: number, d1: Fact): Fact[] {
    const facts = this.summaryFacts.get(summaryKey(sp, d1));
    if (!facts) { return []; }
    return Array.from(facts.values());
  }

  /** When a new summary edge is produced, push it back to any waiting callers. */
  private applyPendingCallers(sp: number, d1: Fact, d2: Fact): void {
    const list = this.pendingCallers.get(summaryKey(sp, d1));
    if (!list) { return; }
    for (const caller of list) {
      const call = this.graph.statements.get(caller.callSite) as
        | Extract<Statement, { kind: 'call' }>
        | undefined;
      if (!call) { continue; }
      const retStmt = this.graph.statements.get(call.returnSite) as
        | Extract<Statement, { kind: 'returnSite' }>
        | undefined;
      const callee = call.calleeProc != null
        ? this.graph.procedures.get(call.calleeProc)
        : undefined;
      if (!callee) { continue; }
      for (const d5 of this.returnFlow(d2, call, retStmt, callee)) {
        this.propagate({
          sp: caller.callerSp,
          d1: caller.callerD1,
          n: call.returnSite,
          d2: d5,
        });
      }
    }
  }

  // ── Flow functions ──────────────────────────────────────────────────────

  /**
   * Flow across an intra-procedural CFG edge n→m. Most statement effects are
   * realized here: source/assign/sanitize/sink all act on d2 at the source of
   * the edge and produce facts at m. The exit statement is handled separately
   * (as a summary update), and call is handled via handleCall.
   *
   * `nStmt` is the statement at the CFG edge's source; `mStmt` is the one at
   * the target. We use `nStmt` because IFDS conventionally models the effect
   * of executing node n on the way out of it.
   */
  private applyFlow(
    nStmt: Statement | undefined,
    _mStmt: Statement | undefined,
    d: Fact,
    _proc: Procedure,
  ): Fact[] {
    if (!nStmt) { return [d]; }
    switch (nStmt.kind) {
      case 'entry':
      case 'returnSite':
      case 'noop':
      case 'return':
        return [d];

      case 'source': {
        // Generate taint on lhs for the zero-fact. Preserve existing facts,
        // but kill any prior taint on lhs (source is a strong assignment).
        if (d.kind === 'zero') {
          return [ZERO, { kind: 'loc', loc: nStmt.lhs }];
        }
        if (locEq(d.loc, nStmt.lhs)) { return []; } // killed by strong assign
        return [d];
      }

      case 'sanitize': {
        // Strong kill of lhs taint, regardless of RHS.
        if (d.kind === 'loc' && locEq(d.loc, nStmt.lhs)) { return []; }
        return [d];
      }

      case 'assign': {
        return this.flowAssign(nStmt.lhs, nStmt.rhs, d);
      }

      case 'sink': {
        // Sink does not alter facts; the finding is produced during
        // collectReachable() after the fixpoint.
        return [d];
      }

      case 'exit':
      case 'call':
        // Handled elsewhere.
        return [d];
    }
  }

  private flowAssign(lhs: Loc, rhs: Rhs, d: Fact): Fact[] {
    const rhsTainted = (fact: Fact): boolean => {
      if (fact.kind === 'zero') { return false; }
      switch (rhs.kind) {
        case 'const': return false;
        case 'var': return locEq(fact.loc, rhs.loc);
        case 'compose': return rhs.parts.some(p => locEq(fact.loc, p));
      }
    };

    // Zero-fact: identity (assign alone doesn't create taint).
    if (d.kind === 'zero') { return [ZERO]; }

    // Strong kill on lhs: we always drop any prior taint on lhs and re-gen
    // based on this RHS.
    if (locEq(d.loc, lhs)) {
      // The incoming d is the pre-assignment taint on lhs; after assignment,
      // lhs's taint depends solely on the RHS. So the pre-fact is killed.
      return [];
    }

    // If d is a source of the RHS, also produce lhs tainted.
    if (rhsTainted(d)) {
      return [d, { kind: 'loc', loc: lhs }];
    }

    return [d];
  }

  private callFlow(d: Fact, actuals: Loc[], callee: Procedure): Fact[] {
    if (d.kind === 'zero') { return [ZERO]; }
    const out: Fact[] = [];
    for (let i = 0; i < actuals.length && i < callee.params.length; i++) {
      if (locEq(d.loc, actuals[i])) {
        out.push({ kind: 'loc', loc: callee.params[i] });
      }
    }
    // Caller-scope facts that aren't mapped to a formal are dropped here —
    // they propagate via the call-to-return edge in callToReturn().
    return out;
  }

  private callToReturn(d: Fact, actuals: Loc[]): Fact[] {
    if (d.kind === 'zero') { return [ZERO]; }
    // Facts equal to an actual are killed here (their flow goes via callFlow).
    for (const a of actuals) {
      if (locEq(d.loc, a)) { return []; }
    }
    // Facts that reference caller-local variables unrelated to this call
    // survive the call transparently.
    return [d];
  }

  private returnFlow(
    exitFact: Fact,
    call: Extract<Statement, { kind: 'call' }>,
    retStmt: Extract<Statement, { kind: 'returnSite' }> | undefined,
    callee: Procedure,
  ): Fact[] {
    if (exitFact.kind === 'zero') { return [ZERO]; }
    // Find the callee's exit return-value fact, if any. The builder records
    // the last `return X` as a statement before the exit; if the callee's
    // exit fact equals the return loc, map it to the caller's return-site
    // `ret` location.
    const exitLoc = exitFact.loc;
    const calleeReturnLocs = this.findReturnLocs(callee);
    for (const rloc of calleeReturnLocs) {
      if (locEq(exitLoc, rloc) && retStmt?.ret) {
        return [{ kind: 'loc', loc: retStmt.ret }];
      }
    }
    // Parameter-tainted-at-exit flowing back to caller-side actual. This lets
    // an "identity-style" callee (no body sanitization) reflect taint on a
    // passed-in parameter back to the caller's variable.
    for (let i = 0; i < callee.params.length; i++) {
      if (locEq(exitLoc, callee.params[i]) && call.args[i]) {
        return [{ kind: 'loc', loc: call.args[i] }];
      }
    }
    return [];
  }

  /** Scan a procedure for `return X` statements and collect their value Locs. */
  private findReturnLocs(proc: Procedure): Loc[] {
    const cached = this.returnLocCache.get(proc.id);
    if (cached) { return cached; }
    const out: Loc[] = [];
    for (const [nodeId, stmt] of this.graph.statements.entries()) {
      if (stmt.kind !== 'return') { continue; }
      const n = this.graph.nodes[nodeId];
      if (n?.procedure !== proc.id) { continue; }
      if (stmt.value) { out.push(stmt.value); }
    }
    this.returnLocCache.set(proc.id, out);
    return out;
  }

  private ownerProc(nodeId: number): Procedure | undefined {
    const n = this.graph.nodes[nodeId];
    if (!n || n.procedure == null) { return undefined; }
    return this.graph.procedures.get(n.procedure);
  }

  /** Emit one Reachability entry per (n, d2) pair in the computed PathEdges. */
  private collectReachable(): Reachability[] {
    const seen = new Set<string>();
    const out: Reachability[] = [];
    for (const key of this.pathEdges) {
      // key format: sp|d1|n|d2
      const parts = key.split('|');
      const n = Number(parts[2]);
      const df = parts[3];
      const dedupKey = `${n}|${df}`;
      if (seen.has(dedupKey)) { continue; }
      seen.add(dedupKey);
      const fact: Fact = df === 'Λ'
        ? ZERO
        : this.parseLocFact(df);
      out.push({ node: n, fact });
    }
    return out;
  }

  private parseLocFact(df: string): Fact {
    const sep = df.indexOf('::');
    if (sep < 0) { return ZERO; }
    const proc = Number(df.slice(0, sep));
    const name = df.slice(sep + 2);
    return { kind: 'loc', loc: { proc, name } };
  }

  /** Public query: is `loc` tainted at `node`? */
  public isLocTaintedAt(node: number, loc: Loc): boolean {
    const reach = this.reachCache ?? this.collectReachable();
    return reach.some(r =>
      r.node === node && r.fact.kind === 'loc' && locEq(r.fact.loc, loc));
  }
}
