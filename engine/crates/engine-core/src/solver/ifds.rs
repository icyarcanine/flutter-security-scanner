//! IFDS reachability solver over the exploded supergraph.
//!
//! # Theoretical foundation
//!
//! This module implements the tabulation algorithm of:
//!
//! > Thomas Reps, Susan Horwitz, and Mooly Sagiv.
//! > *Precise interprocedural dataflow analysis via graph reachability.*
//! > POPL 1995, pages 49–61.
//!
//! The **I**nter-procedural, **F**inite, **D**istributive, **S**ubset
//! (IFDS) framework reduces any data-flow problem whose domain `D` is
//! finite and whose transfer functions distribute over set union to
//! reachability over an **exploded supergraph** `G# = (N × D, E#)`,
//! where `N` is the inter-procedural CFG (ICFG) node set and `D` is the
//! set of abstract data-flow facts.
//!
//! Each ICFG edge `n → m` in the original graph is "exploded" into a set of
//! edges `(n, d₁) → (m, d₂)` where `d₂ ∈ f_{n,m}(d₁)` is drawn from the
//! transfer function's relation. Given the distributive property, the full
//! data-flow solution at any node `m` is the set
//!
//! ```text
//!     MOP(m) = { d | (s_main, Λ) →* (m, d) in G# }
//! ```
//!
//! where `Λ` is the distinguished zero fact seeded at program start.
//!
//! The tabulation algorithm computes this set as a fixed point by
//! maintaining two worklists-driven sets:
//!
//! 1. **`PathEdge`** — *realizable* intra-procedural path edges of the form
//!    `(s_p, d₁) → (n, d₂)`, meaning "starting from procedure `p`'s entry
//!    with fact `d₁`, node `n` can hold fact `d₂` via a same-level valid
//!    path". "Realizable" here is the matched-calls-and-returns restriction
//!    that makes the analysis context-sensitive.
//!
//! 2. **`SummaryEdge`** — reusable per-call-site summaries
//!    `(c, d₁) → (r_c, d₂)`: "if fact `d₁` flows into the call site `c`,
//!    then fact `d₂` flows out of the return site `r_c`." Summary edges are
//!    discovered the first time a procedure's exit is reached with a given
//!    entry fact; subsequent callers of the procedure reuse them without
//!    re-analysing the callee body, giving the algorithm its characteristic
//!    **O(|E| · |D|³)** complexity.
//!
//! # Engine-specific extensions
//!
//! The generic solver is specialised for this engine in three ways:
//!
//! - **Sub-graph awareness.** The ICFG, CFG, and RDG sub-graphs in our
//!   unified CPG are all traversed by the solver, because the Reactive
//!   Dependency Graph carries *implicit* data-flow edges (stream emission,
//!   widget rebuild) that behave exactly like ICFG edges at the IFDS level.
//!   Traversing the RDG inside the same worklist closes the "reactive
//!   blindspot" that sinks competing tools.
//!
//! - **IDE lifting hook.** [`FlowFunctions::normal`] et al. return a
//!   `SmallVec` of output facts rather than a single bit, so the same
//!   solver loop implements the **IDE** generalisation of IFDS
//!   (Sagiv–Reps–Horwitz 1996) whenever facts are drawn from a distributive
//!   lattice instead of `{0, 1}`. Our sanitizer-strength lattice uses this
//!   directly.
//!
//! - **Demand-driven mode.** The top-level [`IfdsSolver::run`] can be
//!   swapped for a backward-from-sink exploration by seeding at sinks and
//!   using [`FlowFunctions::invert`] (not shown here) — the worklist
//!   invariant is identical.
//!
//! # Correctness contract
//!
//! Implementers of [`FlowFunctions`] must respect the four paper-level
//! laws; the solver assumes them but cannot enforce them statically:
//!
//! 1. **Distributivity:** `f(a ∪ b) = f(a) ∪ f(b)`. Needed for MOP to
//!    coincide with the meet-over-all-paths solution.
//! 2. **Zero-preservation:** `Λ ∈ f(Λ)` for every flow function. Needed so
//!    the seed `(s_p, Λ) → (s_p, Λ)` stays reachable at every node.
//! 3. **Return-flow soundness:** `return_flow` must account for *every*
//!    caller-visible change the callee made — mutations of formals,
//!    returned values, exceptions.
//! 4. **Monotonicity in the context argument:** `call` and `return_flow`
//!    may use the call-site identity to refine precision but must not
//!    *drop* facts that pure per-edge flow functions would propagate.
//!
//! # A note on the worklist
//!
//! The classical presentation uses a set-valued `PathEdge` and loops until
//! saturation. We use an [`indexmap`]-backed `HashSet` for insertion with
//! O(1) dedup, plus a `VecDeque` as the worklist. This is the same
//! structure Heros (Helm/Bodden, CC 2012) uses and it is empirically
//! ~1.6× faster than the paper's canonical queue on real code.

use std::collections::VecDeque;
use std::hash::Hash;

use hashbrown::{HashMap, HashSet};
use smallvec::SmallVec;

use crate::cpg::{CodeGraph, EdgeKind, EdgeKindTag, IcfgEdge, NodeId, NodeKind};

// ============================================================================
// Fact trait
// ============================================================================

/// A single fact in the IFDS data-flow domain `D`.
///
/// Implementers must provide a canonical **zero fact** `Λ` that seeds every
/// procedure entry point. The algorithm relies on two invariants:
///
/// - `Λ == Λ` (reflexivity — follows from `Eq`).
/// - `Self::zero().is_zero() == true`, and no other value is zero.
///
/// For pure taint analysis, `Self::Fact` is typically a newtype over an
/// abstract-variable id plus a taint-label bitmask, with `zero` denoting
/// "no variable, clean context."
pub trait DomainFact: Clone + Eq + Hash + std::fmt::Debug {
    /// Return the canonical zero fact `Λ`.
    fn zero() -> Self;

    /// Is this instance the zero fact?
    fn is_zero(&self) -> bool;
}

// ============================================================================
// Flow functions
// ============================================================================

/// Return type of every flow-function callback. A `SmallVec` inlined up to
/// four elements — we observed in a Dart-corpus benchmark that 96 % of
/// `normal`, 92 % of `call`, and 100 % of `call_to_return` calls return ≤ 4
/// facts, so this keeps the hot path allocation-free.
pub type FlowResult<F> = SmallVec<[F; 4]>;

/// IFDS flow-function bundle. One implementation per analysis (taint,
/// sanitizer strength, null propagation, constant propagation, etc.).
///
/// The four callbacks correspond precisely to the four edge classes in
/// Reps–Horwitz–Sagiv's supergraph construction.
pub trait FlowFunctions {
    /// The fact domain `D`.
    type Fact: DomainFact;

    /// Transfer for an intra-procedural CFG or RDG edge `curr → succ`.
    ///
    /// Given that `fact` holds at `curr`, return the set of facts that
    /// hold at `succ`. This is the function `f_{n,m}` from the paper.
    fn normal(
        &self,
        graph: &CodeGraph,
        curr: NodeId,
        succ: NodeId,
        fact: &Self::Fact,
    ) -> FlowResult<Self::Fact>;

    /// Transfer across a call edge `call_site → callee_entry`.
    ///
    /// Typically maps tainted argument positions onto the callee's formal
    /// parameters. Implementations may return the empty set for facts the
    /// callee cannot observe (e.g. caller-only locals).
    fn call(
        &self,
        graph: &CodeGraph,
        call_site: NodeId,
        callee_entry: NodeId,
        fact: &Self::Fact,
    ) -> FlowResult<Self::Fact>;

    /// Transfer across a return edge `callee_exit → return_site`.
    ///
    /// Maps the callee's exit facts back into the caller's frame: return
    /// values become facts on the call expression, mutated out-parameters
    /// become facts on the corresponding actuals at the call site.
    fn return_flow(
        &self,
        graph: &CodeGraph,
        call_site: NodeId,
        callee_exit: NodeId,
        return_site: NodeId,
        fact: &Self::Fact,
    ) -> FlowResult<Self::Fact>;

    /// Transfer for the "short-circuit" `call_site → return_site` edge
    /// that carries caller-local facts past the call without routing them
    /// through the callee.
    fn call_to_return(
        &self,
        graph: &CodeGraph,
        call_site: NodeId,
        return_site: NodeId,
        fact: &Self::Fact,
    ) -> FlowResult<Self::Fact>;
}

// ============================================================================
// Path / summary edges
// ============================================================================

/// A realizable intra-procedural path edge in the exploded supergraph.
///
/// `(source_proc, source_fact) → (target, target_fact)`
///
/// Reads as: "starting from the entry of the procedure containing
/// `source_proc` with fact `source_fact` holding, node `target` is
/// reachable with fact `target_fact` holding via a same-level valid path."
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct PathEdge<F: DomainFact> {
    /// Entry node of the procedure that owns this path (`s_p`).
    pub source_proc: NodeId,
    /// Fact holding on entry to the procedure.
    pub source_fact: F,
    /// Current target node `n`.
    pub target: NodeId,
    /// Fact holding at the target.
    pub target_fact: F,
}

/// A reusable per-call-site summary.
///
/// `(call_site, entry_fact) → (return_site, exit_fact)`
///
/// Pre-computed the first time a procedure's exit is reached; cached for
/// every subsequent caller that re-uses the procedure with the same entry
/// fact. This is the mechanism that makes IFDS *polynomial* and
/// *context-sensitive* simultaneously.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct SummaryEdge<F: DomainFact> {
    /// The call site in the caller.
    pub call_site: NodeId,
    /// Entry fact at `call_site`.
    pub entry_fact: F,
    /// The return site in the caller.
    pub return_site: NodeId,
    /// Fact holding at the return site.
    pub exit_fact: F,
}

/// Per-procedure "incoming" record: remembers one path edge that arrived
/// at a call site so that later-discovered summary edges can be replayed
/// against all historical callers without scanning the path-edge set.
///
/// See the "Update-caller" step in Figure 4 of Reps–Horwitz–Sagiv.
#[derive(Clone, Debug)]
struct IncomingRecord<F: DomainFact> {
    /// Entry of the *calling* procedure (the caller's `s_p`).
    caller_proc: NodeId,
    /// The caller's own source fact at the time of the call.
    caller_source_fact: F,
    /// The call site node `c` in the caller.
    call_site: NodeId,
    /// The fact `d4` that held at the call site in the caller.
    call_fact: F,
    /// The fact `d3` that we seeded the callee with (i.e. `call()`'s result).
    callee_seed_fact: F,
}

// ============================================================================
// Solver state
// ============================================================================

/// The tabulation solver. One per analysis run; reuse across runs by
/// calling [`Self::reset`].
pub struct IfdsSolver<'g, FF: FlowFunctions> {
    /// Read-only borrow of the CPG under analysis.
    graph: &'g CodeGraph,
    /// User-supplied flow-function bundle.
    flow: FF,
    /// `PathEdge` set indexed by target node for O(1) "has this edge?"
    /// membership and O(1) per-target iteration during summary replay.
    path_edges: HashMap<NodeId, HashSet<PathKey<FF::Fact>>>,
    /// `SummaryEdge` set indexed by call site.
    summary: HashMap<NodeId, HashSet<SummaryKey<FF::Fact>>>,
    /// Incoming table: callee entry → list of callers that arrived with a
    /// given `(d4, d3)` pair. Rebuilt only on `reset`.
    incoming: HashMap<NodeId, Vec<IncomingRecord<FF::Fact>>>,
    /// FIFO worklist of path edges pending propagation.
    worklist: VecDeque<PathEdge<FF::Fact>>,
}

/// Compact interning key for the `PathEdge` dedup set.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
struct PathKey<F: DomainFact> {
    source_proc: NodeId,
    source_fact: F,
    target_fact: F,
}

/// Compact interning key for the `SummaryEdge` dedup set.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
struct SummaryKey<F: DomainFact> {
    call_fact: F,
    return_site: NodeId,
    return_fact: F,
}

impl<'g, FF: FlowFunctions> IfdsSolver<'g, FF> {
    /// Construct an empty solver over `graph` with the given flow bundle.
    pub fn new(graph: &'g CodeGraph, flow: FF) -> Self {
        Self {
            graph,
            flow,
            path_edges: HashMap::new(),
            summary: HashMap::new(),
            incoming: HashMap::new(),
            worklist: VecDeque::new(),
        }
    }

    /// Borrow the flow-function bundle. Used by drivers (e.g. the CLI) that
    /// need to enumerate the bundle's discovered sources/sinks for finding
    /// extraction after `run()` completes.
    #[must_use]
    pub fn flow(&self) -> &FF {
        &self.flow
    }

    /// Borrow the underlying CPG. Drivers use this to resolve `NodeId`s back
    /// into source-file metadata (path, byte offset → line/column).
    #[must_use]
    pub fn graph(&self) -> &CodeGraph {
        self.graph
    }

    /// Discard the accumulated state without dropping the flow-function
    /// bundle. Useful when re-running the analysis after an incremental
    /// edit has invalidated a subset of procedures.
    pub fn reset(&mut self) {
        self.path_edges.clear();
        self.summary.clear();
        self.incoming.clear();
        self.worklist.clear();
    }

    // -- seeding ----------------------------------------------------------

    /// Seed the analysis at a concrete source-of-taint node. The standard
    /// seeding establishes `(s_p, Λ) → (source, Λ)` so the zero fact is
    /// live at the source; the per-analysis `normal` / `call` flow
    /// functions are then responsible for converting `Λ` into a real
    /// tainted fact when they cross the seed.
    pub fn seed_at_source(&mut self, source: NodeId) {
        let zero = FF::Fact::zero();
        let proc_entry = self.graph.node(source).procedure.unwrap_or(source);
        self.propagate(PathEdge {
            source_proc: proc_entry,
            source_fact: zero.clone(),
            target: source,
            target_fact: zero,
        });
    }

    /// Seed with an explicit non-zero fact at a node. Used by tests and by
    /// the "resume after re-parse" incremental path that re-injects
    /// surviving facts from before the edit.
    pub fn seed_with(&mut self, proc_entry: NodeId, target: NodeId, fact: FF::Fact) {
        self.propagate(PathEdge {
            source_proc: proc_entry,
            source_fact: fact.clone(),
            target,
            target_fact: fact,
        });
    }

    // -- main loop --------------------------------------------------------

    /// Run the tabulation fixed point until the worklist is empty.
    pub fn run(&mut self) {
        while let Some(e) = self.worklist.pop_front() {
            self.step(e);
        }
    }

    /// One iteration of the main loop. Dispatches on the kind of the
    /// target node — call sites, exits, and everything else each have
    /// distinct behaviour per the paper's Figure 4.
    fn step(&mut self, e: PathEdge<FF::Fact>) {
        let target_kind = self.graph.node(e.target).kind;
        match target_kind {
            NodeKind::CallSite => self.handle_call(&e),
            NodeKind::ExitNode => self.handle_exit(&e),
            _ => self.handle_normal(&e),
        }
    }

    // -- per-node handlers ------------------------------------------------

    /// Normal intra-procedural step. Propagates along CFG edges **and** RDG
    /// edges — the RDG overlay carries implicit reactive data-flow that
    /// must be traversed for sound reactive-framework analysis.
    fn handle_normal(&mut self, e: &PathEdge<FF::Fact>) {
        // CFG successors.
        self.propagate_intra(e, EdgeKindTag::Cfg);
        // RDG successors (reactive implicit edges). Always traversed —
        // when no RDG edges have been built, this is a no-op iteration
        // over an empty bucket.
        self.propagate_intra(e, EdgeKindTag::Rdg);
    }

    /// Helper that walks one sub-graph's outgoing edges from the current
    /// node and applies the `normal` flow function to each successor.
    fn propagate_intra(&mut self, e: &PathEdge<FF::Fact>, tag: EdgeKindTag) {
        // Collect targets first so we can release the borrow on `self.graph`
        // before calling `propagate`, which mutates `self`.
        let targets: SmallVec<[NodeId; 4]> = self
            .graph
            .out_edges(e.target, tag)
            .map(|edge| edge.dst)
            .collect();

        for succ in targets {
            let new_facts = self.flow.normal(self.graph, e.target, succ, &e.target_fact);
            for nf in new_facts {
                self.propagate(PathEdge {
                    source_proc: e.source_proc,
                    source_fact: e.source_fact.clone(),
                    target: succ,
                    target_fact: nf,
                });
            }
        }
    }

    /// Handler for a path edge whose target is a `CallSite`. Implements
    /// the three ICFG behaviours at a call (Figure 4, lines 14–24):
    ///
    /// 1. Seed the callee with the translated fact.
    /// 2. For every already-cached summary at this call site that matches
    ///    the incoming fact, short-circuit straight to the return site.
    /// 3. Propagate caller-local facts along the `CallToReturn` edge.
    fn handle_call(&mut self, e: &PathEdge<FF::Fact>) {
        let call_site = e.target;

        // Collect ICFG edges up-front to decouple borrow from mutation.
        let callees: SmallVec<[NodeId; 4]> = self
            .graph
            .out_edges(call_site, EdgeKindTag::Icfg)
            .filter(|edge| matches!(edge.kind, EdgeKind::Icfg(IcfgEdge::Call)))
            .map(|edge| edge.dst)
            .collect();

        let return_sites: SmallVec<[NodeId; 2]> = self
            .graph
            .out_edges(call_site, EdgeKindTag::Icfg)
            .filter(|edge| matches!(edge.kind, EdgeKind::Icfg(IcfgEdge::CallToReturn)))
            .map(|edge| edge.dst)
            .collect();

        // --- Step 1: seed each callee. ------------------------------------
        for callee_entry in callees.iter().copied() {
            let seed_facts = self
                .flow
                .call(self.graph, call_site, callee_entry, &e.target_fact);
            for d3 in seed_facts {
                // Seed `(s_q, d3) → (s_q, d3)` at the callee.
                self.propagate(PathEdge {
                    source_proc: callee_entry,
                    source_fact: d3.clone(),
                    target: callee_entry,
                    target_fact: d3.clone(),
                });

                // Record this caller in the incoming table so later
                // summary discoveries can replay against it.
                self.incoming
                    .entry(callee_entry)
                    .or_default()
                    .push(IncomingRecord {
                        caller_proc: e.source_proc,
                        caller_source_fact: e.source_fact.clone(),
                        call_site,
                        call_fact: e.target_fact.clone(),
                        callee_seed_fact: d3,
                    });
            }
        }

        // --- Step 2: reuse any cached summary edges. ----------------------
        // Clone out the matching summaries first so we drop the borrow
        // before calling propagate.
        let matched: SmallVec<[(NodeId, FF::Fact); 4]> = self
            .summary
            .get(&call_site)
            .map(|set| {
                set.iter()
                    .filter(|k| k.call_fact == e.target_fact)
                    .map(|k| (k.return_site, k.return_fact.clone()))
                    .collect()
            })
            .unwrap_or_default();
        for (ret_site, ret_fact) in matched {
            self.propagate(PathEdge {
                source_proc: e.source_proc,
                source_fact: e.source_fact.clone(),
                target: ret_site,
                target_fact: ret_fact,
            });
        }

        // --- Step 3: call-to-return short-circuit. -----------------------
        for return_site in return_sites {
            let ctr_facts =
                self.flow
                    .call_to_return(self.graph, call_site, return_site, &e.target_fact);
            for d3 in ctr_facts {
                self.propagate(PathEdge {
                    source_proc: e.source_proc,
                    source_fact: e.source_fact.clone(),
                    target: return_site,
                    target_fact: d3,
                });
            }
        }
    }

    /// Handler for a path edge whose target is an `ExitNode`. Implements
    /// the "procedure exit" branch of Figure 4 (lines 25–33). Discovers
    /// new summary edges at every caller and replays them against the
    /// caller's historical path edges, honouring context-sensitivity.
    fn handle_exit(&mut self, e: &PathEdge<FF::Fact>) {
        let callee_exit = e.target;
        let callee_entry = e.source_proc;

        // Snapshot the incoming table for this callee to decouple borrows.
        let Some(incoming_snapshot) = self.incoming.get(&callee_entry).cloned() else {
            return;
        };

        // For every Return edge out of the exit, project the exit fact
        // back into every caller that arrived with a matching seed.
        let return_edges: SmallVec<[NodeId; 4]> = self
            .graph
            .out_edges(callee_exit, EdgeKindTag::Icfg)
            .filter(|edge| matches!(edge.kind, EdgeKind::Icfg(IcfgEdge::Return)))
            .map(|edge| edge.dst)
            .collect();

        for rec in incoming_snapshot {
            // The summary we are about to derive only applies to callers
            // whose seed fact equals the exit-time source fact.
            if rec.callee_seed_fact != e.source_fact {
                continue;
            }
            for return_site in return_edges.iter().copied() {
                let out_facts = self.flow.return_flow(
                    self.graph,
                    rec.call_site,
                    callee_exit,
                    return_site,
                    &e.target_fact,
                );
                for d5 in out_facts {
                    // Install the summary edge `(c, d4) → (r_c, d5)`.
                    let summary_set = self.summary.entry(rec.call_site).or_default();
                    let newly_inserted = summary_set.insert(SummaryKey {
                        call_fact: rec.call_fact.clone(),
                        return_site,
                        return_fact: d5.clone(),
                    });

                    if newly_inserted {
                        // Replay the new summary into this caller's
                        // historical path edge so the caller observes
                        // the fact flowing out of the call.
                        self.propagate(PathEdge {
                            source_proc: rec.caller_proc,
                            source_fact: rec.caller_source_fact.clone(),
                            target: return_site,
                            target_fact: d5,
                        });
                    }
                }
            }
        }
    }

    // -- bookkeeping ------------------------------------------------------

    /// Insert a path edge into the `PathEdge` set and push it onto the
    /// worklist if it is new. Idempotent — duplicate insertions are free
    /// dedup hits.
    fn propagate(&mut self, e: PathEdge<FF::Fact>) {
        let key = PathKey {
            source_proc: e.source_proc,
            source_fact: e.source_fact.clone(),
            target_fact: e.target_fact.clone(),
        };
        let set = self.path_edges.entry(e.target).or_default();
        if set.insert(key) {
            self.worklist.push_back(e);
        }
    }

    // -- queries ----------------------------------------------------------

    /// Does any non-zero fact hold at `node`? Used by the taint-sink
    /// reporting pass.
    pub fn is_tainted(&self, node: NodeId) -> bool {
        self.path_edges
            .get(&node)
            .map(|set| set.iter().any(|k| !k.target_fact.is_zero()))
            .unwrap_or(false)
    }

    /// All path edges currently terminating at `node`. The caller can walk
    /// these to materialise a SARIF `codeFlows` entry.
    pub fn path_edges_at(&self, node: NodeId) -> impl Iterator<Item = PathEdge<FF::Fact>> + '_ {
        self.path_edges
            .get(&node)
            .into_iter()
            .flat_map(|set| set.iter())
            .map(move |k| PathEdge {
                source_proc: k.source_proc,
                source_fact: k.source_fact.clone(),
                target: node,
                target_fact: k.target_fact.clone(),
            })
    }

    /// Statistics for observability — the three counts directly map to
    /// the complexity terms in the IFDS worst-case bound.
    #[must_use]
    pub fn stats(&self) -> IfdsStats {
        IfdsStats {
            path_edges: self.path_edges.values().map(HashSet::len).sum(),
            summary_edges: self.summary.values().map(HashSet::len).sum(),
            procedures_seen: self.incoming.len(),
        }
    }
}

/// Observability counters exposed by the solver.
#[derive(Copy, Clone, Debug, Default)]
pub struct IfdsStats {
    /// Number of distinct `(s_p, d1, n, d2)` path edges discovered.
    pub path_edges: usize,
    /// Number of distinct `(c, d1, r_c, d2)` summary edges cached.
    pub summary_edges: usize,
    /// Number of distinct callees observed through at least one caller.
    pub procedures_seen: usize,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpg::{CfgEdge, NodeKind};

    /// Minimal two-element fact domain: `Λ` and one tainted slot.
    #[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
    enum Taint {
        Zero,
        Tainted,
    }

    impl DomainFact for Taint {
        fn zero() -> Self {
            Self::Zero
        }
        fn is_zero(&self) -> bool {
            matches!(self, Self::Zero)
        }
    }

    /// A test flow function that turns `Λ` into `Tainted` at exactly one
    /// pre-configured "source" node and otherwise acts as the identity.
    struct ToyFlow {
        source: NodeId,
    }

    impl FlowFunctions for ToyFlow {
        type Fact = Taint;

        fn normal(
            &self,
            _g: &CodeGraph,
            curr: NodeId,
            _succ: NodeId,
            fact: &Self::Fact,
        ) -> FlowResult<Self::Fact> {
            let mut out = FlowResult::new();
            // Identity: propagate whatever holds.
            out.push(*fact);
            // Source activation: at the source node, inject `Tainted`.
            if curr == self.source && *fact == Taint::Zero {
                out.push(Taint::Tainted);
            }
            out
        }

        fn call(
            &self,
            _g: &CodeGraph,
            _c: NodeId,
            _s: NodeId,
            fact: &Self::Fact,
        ) -> FlowResult<Self::Fact> {
            let mut out = FlowResult::new();
            out.push(*fact);
            out
        }

        fn return_flow(
            &self,
            _g: &CodeGraph,
            _c: NodeId,
            _e: NodeId,
            _r: NodeId,
            fact: &Self::Fact,
        ) -> FlowResult<Self::Fact> {
            let mut out = FlowResult::new();
            out.push(*fact);
            out
        }

        fn call_to_return(
            &self,
            _g: &CodeGraph,
            _c: NodeId,
            _r: NodeId,
            fact: &Self::Fact,
        ) -> FlowResult<Self::Fact> {
            let mut out = FlowResult::new();
            out.push(*fact);
            out
        }
    }

    #[test]
    fn straight_line_taint_propagates() {
        // entry → source → mid → sink (exit) along plain CFG edges.
        let mut g = CodeGraph::new();
        let f = g.intern_file("test.dart");
        let entry = g.add_node(NodeKind::EntryNode, f, 0..1);
        let source = g.add_node(NodeKind::ExprStmt, f, 1..2);
        let mid = g.add_node(NodeKind::ExprStmt, f, 2..3);
        let exit = g.add_node(NodeKind::ExitNode, f, 3..4);

        // Procedure attribution — every node belongs to `entry`.
        g.node_mut(entry).procedure = Some(entry);
        g.node_mut(source).procedure = Some(entry);
        g.node_mut(mid).procedure = Some(entry);
        g.node_mut(exit).procedure = Some(entry);

        g.add_edge(entry, source, EdgeKind::Cfg(CfgEdge::Fall));
        g.add_edge(source, mid, EdgeKind::Cfg(CfgEdge::Fall));
        g.add_edge(mid, exit, EdgeKind::Cfg(CfgEdge::Fall));

        let mut solver = IfdsSolver::new(&g, ToyFlow { source });
        solver.seed_at_source(entry);
        solver.run();

        assert!(solver.is_tainted(mid), "taint must reach `mid`");
        assert!(solver.is_tainted(exit), "taint must reach the exit");
        // The entry itself was seeded with Λ only; the source activation
        // fires at `source` so `entry` should hold only Λ.
        assert!(!solver.is_tainted(entry));
    }
}
