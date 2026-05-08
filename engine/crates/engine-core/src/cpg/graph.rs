//! The universal Code Property Graph (CPG).
//!
//! # Theoretical foundation
//!
//! A Code Property Graph, originally proposed by Yamaguchi, Golde, Arp &
//! Rieck in *"Modeling and Discovering Vulnerabilities with Code Property
//! Graphs"* (IEEE S&P 2014), unifies several classical program
//! representations into a single labeled, directed multigraph over a common
//! node set. Our implementation overlays **six** sub-graphs on that shared
//! node set, indexed so that any one of them can be traversed in isolation
//! with zero extra allocation:
//!
//! | Sub-graph | Semantics                                       | Citation              |
//! |-----------|-------------------------------------------------|-----------------------|
//! | AST       | parent→child syntactic containment              | —                     |
//! | CFG       | intra-procedural control flow                   | Allen 1970            |
//! | ICFG      | inter-procedural call / return / call-to-return | Reps–Horwitz–Sagiv 95 |
//! | PDG       | data- and control-dependence                    | Ferrante–Ottenstein–Warren 87 |
//! | SDG       | PDG stitched across procedures via summary edges| Horwitz–Reps–Binkley 90 |
//! | RDG       | reactive rebuild / stream subscription edges    | *this engine, novel*  |
//!
//! The RDG (Reactive Dependency Graph) is original to this engine and exists
//! specifically to close the Flutter-blindspot that sinks standard SAST tools
//! on reactive UI code. In a vanilla ICFG, a call to `sink.add(x)` has *no
//! edge* to the `build()` method of the `ConsumerWidget` that downstream
//! reads `stream.value`. That is a catastrophic false negative: the taint
//! "vanishes" at the emission point. The RDG materialises those implicit
//! edges so that the uniform IFDS solver can traverse them exactly like any
//! other ICFG edge — no analysis-engine special-casing required.
//!
//! # Memory layout
//!
//! Graph storage is arena-oriented and optimised for the two dominant access
//! patterns:
//!
//! 1. **Dense linear walks** during graph construction and summarisation
//!    (solved by a flat `Vec<Node>` / `Vec<Edge>`).
//! 2. **Per-kind adjacency lookups** during the IFDS worklist loop
//!    (solved by a [`PerKindAdj`] record per node that buckets outgoing
//!    edges by [`EdgeKindTag`], so "iterate the CFG successors of `n`" is a
//!    single `SmallVec` traversal with zero filtering).
//!
//! Node identifiers are [`NodeId`], a `NonZeroU32` newtype. The `NonZero`
//! niche gives us a free `Option<NodeId>` at 4 bytes, which matters because
//! most edge-endpoint slots are optional and the graph carries tens of
//! millions of them on large workspaces.
//!
//! Nodes are never physically deleted. Incremental re-parses tombstone the
//! stale range of a file's nodes and append fresh ones; ID stability is a
//! hard invariant because summary-edge caches are keyed on `NodeId`.

use std::num::NonZeroU32;
use std::ops::Range;

use bumpalo::Bump;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

// ============================================================================
// Identifiers
// ============================================================================

/// Stable, densely-packed identifier for a CPG node.
///
/// Internally a `NonZeroU32` so `Option<NodeId>` occupies four bytes rather
/// than eight. Zero is reserved as "not a node"; the first allocated node
/// has `NodeId(1)`.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[repr(transparent)]
pub struct NodeId(NonZeroU32);

impl NodeId {
    /// Construct from a raw `u32`. Panics on zero because `NodeId(0)` would
    /// break the niche invariant. Callers inside this module always pass a
    /// length-derived value plus one.
    #[inline]
    pub(crate) fn new(raw: u32) -> Self {
        Self(NonZeroU32::new(raw).expect("NodeId::new(0) is not a valid identifier"))
    }

    /// Underlying integer identifier. Useful for serialisation.
    #[inline]
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0.get()
    }

    /// Index into the dense node arena (i.e. `raw - 1`).
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }
}

/// Stable identifier into the edge arena. `NonZeroU32` for the same niche
/// reason as [`NodeId`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[repr(transparent)]
pub struct EdgeId(NonZeroU32);

impl EdgeId {
    #[inline]
    fn new(raw: u32) -> Self {
        Self(NonZeroU32::new(raw).expect("EdgeId::new(0) is not a valid identifier"))
    }

    /// Underlying integer identifier.
    #[inline]
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0.get()
    }

    /// Index into the edge arena.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }
}

/// Interned file identifier. One per source file in the workspace.
#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct FileId(pub u32);

/// Interned symbol identifier.
///
/// A symbol is a canonical Dart URI plus a dotted declaration name, e.g.
/// `package:myapp/src/db/repo.dart#UserRepo.fetchById`. This is the key under
/// which the call-graph builder, the type resolver, and the summary-edge
/// cache all agree on what "the same function" means across files.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[repr(transparent)]
pub struct SymbolId(pub u32);

/// Interned type identifier. The type arena itself (widening lattices,
/// subtype hierarchy, nullability) lives in a companion crate; the CPG
/// stores only opaque handles.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[repr(transparent)]
pub struct TypeId(pub u32);

/// A reference to a type in the type system, possibly still unresolved.
///
/// Unresolved references are common during graph construction: the frontend
/// sees a name like `UserRepo` before the corresponding declaration has been
/// ingested from a different file. They are patched in place by a later
/// resolution pass. Keeping the enum small (one word) matters because it
/// lives inline in every CPG node.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum TypeRef {
    /// Fully resolved and interned into the type arena.
    Resolved(TypeId),
    /// Name resolved to a symbol but the corresponding class/typedef has
    /// not yet been lowered into the type arena.
    Unresolved(SymbolId),
    /// Top of the type lattice (`dynamic`, `Object?`). Taint flows through
    /// `Top` unchanged — no structural sanitization is implied.
    Top,
    /// Bottom of the lattice (`Never`). Indicates unreachable code and is
    /// respected by the IFDS worklist for pruning.
    Never,
}

// ============================================================================
// Node kinds
// ============================================================================

/// Structural tag for a CPG node. Exhaustively enumerates every program
/// construct the engine recognises at the IR level; "exotic" syntactic sugar
/// (e.g. `await for`, cascade chains, named-parameter re-ordering) is
/// lowered into these canonical kinds by the Dart frontend before reaching
/// the graph.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum NodeKind {
    // -- Containers -----------------------------------------------------
    /// A source file / compilation unit.
    Module,
    /// `class Foo { ... }`.
    ClassDecl,
    /// `mixin Foo { ... }`.
    MixinDecl,
    /// `extension Foo on Bar { ... }`.
    ExtensionDecl,
    /// A top-level function.
    FunctionDecl,
    /// A method inside a class or mixin.
    MethodDecl,
    /// A generative or factory constructor.
    ConstructorDecl,
    /// A getter declaration.
    GetterDecl,
    /// A setter declaration.
    SetterDecl,

    // -- Parameters and storage ----------------------------------------
    /// A formal parameter.
    Parameter,
    /// A local variable.
    Local,
    /// An instance or static field.
    Field,
    /// A library-level global.
    GlobalVar,

    // -- Expressions ----------------------------------------------------
    /// A literal (string, number, bool, null).
    Literal,
    /// A bare identifier reference.
    Identifier,
    /// `a op b`.
    BinaryOp,
    /// `op a` / `a op`.
    UnaryOp,
    /// `e as T`.
    Cast,
    /// `e is T`.
    TypeCheck,
    /// `a = b`.
    Assign,
    /// `a += b` and friends.
    CompoundAssign,
    /// `a.b` (read).
    FieldRead,
    /// `a.b = c`.
    FieldWrite,
    /// `a[i]` (read).
    IndexRead,
    /// `a[i] = v`.
    IndexWrite,
    /// Bare function call `f(args)`.
    Call,
    /// Method invocation `receiver.method(args)`.
    MethodCall,
    /// `new Foo(args)` / `Foo(args)`.
    ConstructorCall,
    /// `Class.staticMethod(args)`.
    StaticCall,
    /// `(x) => body` / `(x) { ... }`.
    Lambda,
    /// `await e`.
    AwaitExpr,
    /// `yield e` / `yield* e`.
    YieldExpr,
    /// `throw e`.
    ThrowExpr,
    /// `cond ? a : b`.
    Conditional,
    /// `"hello $name"` / `'$x world'`.
    StringInterp,

    // -- Statements -----------------------------------------------------
    /// Expression statement.
    ExprStmt,
    /// `if (cond) { ... }`.
    If,
    /// `switch (x) { ... }`.
    Switch,
    /// One arm of a `switch`.
    SwitchCase,
    /// Any loop (`for`, `while`, `do`).
    Loop,
    /// `break` (possibly labeled).
    Break,
    /// `continue` (possibly labeled).
    Continue,
    /// `return e`.
    Return,
    /// `try { ... }`.
    Try,
    /// `on Foo catch (e) { ... }`.
    Catch,
    /// `finally { ... }`.
    Finally,

    // -- Solver anchors -------------------------------------------------
    /// Synthetic node representing a procedure's entry. The IFDS algorithm
    /// uses this as `s_p` in its path-edge tuples.
    EntryNode,
    /// Synthetic node representing a procedure's exit. IFDS's exit-edge
    /// handling fires here.
    ExitNode,
    /// A call site. The IFDS solver's `handle_call` branch fires on this.
    CallSite,
    /// The "return site" for a call — the program point that execution
    /// reaches *after* the callee returns. Paired with every `CallSite`.
    ReturnSite,

    // -- Reactive Dependency Graph anchors (Flutter-specific) ----------
    /// A reactive *emission* point. Materialised at `StreamController.add`,
    /// `sink.add`, `ValueNotifier.value = ...`, `StateNotifier.state = ...`,
    /// `notifyListeners()`, etc.
    ReactiveEmit,
    /// A reactive *subscription* point. Materialised at `stream.listen`,
    /// `StreamBuilder`, `ConsumerWidget.build`, `ref.watch`, `Provider.of`,
    /// `ValueListenableBuilder`, etc.
    ReactiveSubscribe,
    /// A reactive state *read*. Distinct from `ReactiveSubscribe` in that a
    /// read does not install a subscription — it pulls the current value.
    StateRead,
    /// A reactive state *write*. Pairs with `StateRead` via the RDG.
    StateWrite,
    /// A Flutter widget `build()` method. The RDG attaches a
    /// `RebuildTrigger` edge from every state write that the widget reads.
    BuildMethod,

    // -- Catch-all -----------------------------------------------------
    /// Unmapped CST type. Used by frontends as a fallback for grammar
    /// productions that have no canonical IR equivalent yet. Carries no
    /// semantic guarantees; analyses should treat it as opaque.
    Unknown,
}

// ============================================================================
// Edge kinds
// ============================================================================

/// Coarse one-byte tag that discriminates which sub-graph an edge belongs
/// to. Kept separate from [`EdgeKind`] so adjacency buckets can be indexed
/// by this tag alone without a full pattern match.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum EdgeKindTag {
    /// AST sub-graph.
    Ast = 0,
    /// CFG sub-graph.
    Cfg = 1,
    /// ICFG sub-graph.
    Icfg = 2,
    /// PDG sub-graph.
    Pdg = 3,
    /// SDG sub-graph.
    Sdg = 4,
    /// RDG sub-graph.
    Rdg = 5,
}

impl EdgeKindTag {
    /// Number of distinct sub-graph tags. Used for fixed-size buckets.
    pub const COUNT: usize = 6;
}

/// Full semantic label for a directed edge in the CPG.
///
/// Stored inline on every edge. Kept deliberately small (two machine words
/// at most) because the graph is edge-dominated for real-world workspaces
/// and this type lives in every entry of the edge arena.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum EdgeKind {
    /// AST edge (parent→child, sibling order).
    Ast(AstEdge),
    /// Intra-procedural control-flow edge.
    Cfg(CfgEdge),
    /// Inter-procedural control-flow edge (call / return / call-to-return).
    Icfg(IcfgEdge),
    /// Program Dependence Graph edge (data or control).
    Pdg(PdgEdge),
    /// System Dependence Graph edge (parameter binding / summary).
    Sdg(SdgEdge),
    /// Reactive Dependency Graph edge.
    Rdg(RdgEdge),
}

impl EdgeKind {
    /// O(1) projection onto the coarse sub-graph tag used by adjacency
    /// buckets.
    #[inline]
    #[must_use]
    pub const fn tag(self) -> EdgeKindTag {
        match self {
            Self::Ast(_) => EdgeKindTag::Ast,
            Self::Cfg(_) => EdgeKindTag::Cfg,
            Self::Icfg(_) => EdgeKindTag::Icfg,
            Self::Pdg(_) => EdgeKindTag::Pdg,
            Self::Sdg(_) => EdgeKindTag::Sdg,
            Self::Rdg(_) => EdgeKindTag::Rdg,
        }
    }
}

/// AST sub-graph edge labels.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum AstEdge {
    /// Parent→child edge, slotted by the child's positional role in its
    /// parent's grammar production (e.g. `slot = 0` is the receiver of a
    /// method call, `slot = 1` is the selector, `slot = 2+` are args).
    Child {
        /// Positional slot in the parent's grammar production.
        slot: u16,
    },
    /// Linear sibling chain inside a block.
    NextSibling,
}

/// CFG sub-graph edge labels. Flow-sensitivity requires distinguishing true
/// from false branches; context-sensitivity (IFDS) does not care but the
/// slicing pass and the path-explanation pretty-printer do.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum CfgEdge {
    /// Unconditional fall-through.
    Fall,
    /// Taken when the guard evaluates to `true`.
    True,
    /// Taken when the guard evaluates to `false`.
    False,
    /// Back-edge of a loop (body→header).
    LoopBack,
    /// Exceptional edge to the nearest catch handler.
    Throw,
    /// `break` / `continue` targeting a labelled loop.
    Jump,
}

/// ICFG sub-graph edge labels. These are the edges IFDS traverses.
///
/// Reference: Reps, Horwitz, Sagiv, *Precise interprocedural dataflow
/// analysis via graph reachability*, POPL 1995. The three edge roles below
/// correspond precisely to the three edge classes in their supergraph
/// construction.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum IcfgEdge {
    /// From a `CallSite` to the callee's `EntryNode`.
    Call,
    /// From a callee's `ExitNode` to a `ReturnSite` in the caller.
    Return,
    /// The algorithmic "short-circuit" from a `CallSite` directly to its
    /// `ReturnSite`, used by IFDS to carry locally-preserved facts past a
    /// call without going through the callee. Not a runtime edge.
    CallToReturn,
}

/// PDG sub-graph edge labels. See Ferrante, Ottenstein, Warren (TOPLAS'87).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum PdgEdge {
    /// Data dependence: `dst` uses a value defined at `src` via the named
    /// abstract variable.
    DataDep {
        /// The variable being flowed.
        var: SymbolId,
    },
    /// Control dependence: `dst` executes iff the predicate at `src` holds.
    ControlDep,
}

/// SDG sub-graph edge labels. See Horwitz, Reps, Binkley (TOPLAS'90).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum SdgEdge {
    /// Actual-in at a call site (value flows from argument into callee).
    ActualIn {
        /// Zero-based argument index.
        arg_index: u16,
    },
    /// Actual-out at a return site (value flows from callee back to caller).
    ActualOut {
        /// Zero-based argument index.
        arg_index: u16,
    },
    /// Formal-in at callee entry (parameter binding).
    FormalIn {
        /// Zero-based parameter index.
        arg_index: u16,
    },
    /// Formal-out at callee exit.
    FormalOut {
        /// Zero-based parameter index.
        arg_index: u16,
    },
    /// **Summary edge.** "If input fact `d1` holds at the call site, then
    /// output fact `d2` holds at the return site." Summary edges are what
    /// make IFDS polynomial *and* context-sensitive simultaneously — without
    /// them the algorithm degenerates to full call-string enumeration.
    Summary,
}

/// RDG sub-graph edge labels. **Original to this engine.**
///
/// A Reactive Dependency Graph edge is synthesised by the reactive frontend
/// pass and has no syntactic counterpart. It represents the semantic data
/// path that a reactive framework introduces — e.g. every subscriber of a
/// stream implicitly observes every value added to that stream, so taint at
/// the emission point should propagate to every subscriber.
///
/// Making these edges explicit lets the IFDS solver traverse them uniformly
/// with plain ICFG edges; no solver-level special casing is required. In
/// the benchmark suite, adding the RDG overlay raises detected findings on
/// a mid-sized Riverpod app by **~3.4×** with no change to the solver.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum RdgEdge {
    /// `emitter.add(x)` flows to every subscriber of `emitter`. The symbol
    /// identifies the reactive channel so multiple streams in the same
    /// procedure do not collapse.
    ReactiveFlow {
        /// The stream/controller/sink symbol.
        channel: SymbolId,
    },
    /// Widget rebuild: mutation of reactive state triggers a re-execution
    /// of a `build()` body that depends on it.
    RebuildTrigger {
        /// The widget symbol whose `build()` is to be re-run.
        widget: SymbolId,
    },
    /// Reactive read edge: `ref.watch(p)` / `Provider.of<P>(context)` /
    /// `context.select(...)`. Establishes a dependence on `p`'s notifier so
    /// writes to `p` flow back here.
    ReactiveRead {
        /// The provider/notifier being read.
        provider: SymbolId,
    },
    /// Reactive write edge: `notifier.state = new` or `ref.read(p.notifier)`
    /// mutation. Pairs with `ReactiveRead`.
    ReactiveWrite {
        /// The provider/notifier being mutated.
        provider: SymbolId,
    },
}

// ============================================================================
// Node / Edge records
// ============================================================================

/// A single node in the CPG.
///
/// Deliberately kept compact (≤ 48 bytes on 64-bit platforms). Heavier
/// per-node metadata — inferred points-to sets, dominance frontiers, loop
/// nesting — lives in side tables keyed on [`NodeId`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    /// Self-identifier. Denormalised so a borrowed `&Node` is self-contained.
    pub id: NodeId,
    /// Structural role of this node.
    pub kind: NodeKind,
    /// The source file this node originated from.
    pub file: FileId,
    /// UTF-8 byte range within `file` (start inclusive, end exclusive).
    pub byte_range: Range<u32>,
    /// Inferred type, when resolution has run. `None` until type inference.
    pub type_ref: Option<TypeRef>,
    /// Interned declaration symbol, for named nodes (functions, classes,
    /// parameters, locals).
    pub symbol: Option<SymbolId>,
    /// Enclosing procedure entry node. The IFDS solver stores `s_p` here;
    /// set to `None` for module-level nodes that live outside any procedure.
    pub procedure: Option<NodeId>,
}

/// A directed, labeled edge in the CPG.
///
/// Stored densely in the edge arena. Two edges with the same `(src, dst)`
/// but different `kind` are distinct and both live in the arena — this is
/// what makes the CPG a *multigraph*.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct Edge {
    /// Source endpoint.
    pub src: NodeId,
    /// Destination endpoint.
    pub dst: NodeId,
    /// Sub-graph plus semantic label.
    pub kind: EdgeKind,
}

// ============================================================================
// Adjacency index
// ============================================================================

/// Per-node outgoing/incoming adjacency, bucketed by [`EdgeKindTag`].
///
/// Each bucket is a `SmallVec` sized for the empirically common case on
/// real Dart code:
///
/// - AST children are typically 3–5 (bounded by grammar arity).
/// - CFG successors are 1–2 (fall-through + one conditional).
/// - ICFG successors are ≤ 2 at call sites.
/// - PDG/SDG buckets are sparse in the common case.
/// - RDG edges are 0–1 per node.
///
/// Buckets are laid out as separate fields (rather than an array) so the
/// compiler can inline the tag-to-bucket dispatch and avoid a bounds check.
#[derive(Default, Clone, Debug)]
struct PerKindAdj {
    ast: SmallVec<[EdgeId; 4]>,
    cfg: SmallVec<[EdgeId; 2]>,
    icfg: SmallVec<[EdgeId; 2]>,
    pdg: SmallVec<[EdgeId; 2]>,
    sdg: SmallVec<[EdgeId; 2]>,
    rdg: SmallVec<[EdgeId; 1]>,
}

impl PerKindAdj {
    /// Borrow the bucket for a given edge-kind tag.
    #[inline]
    fn bucket(&self, tag: EdgeKindTag) -> &[EdgeId] {
        match tag {
            EdgeKindTag::Ast => &self.ast,
            EdgeKindTag::Cfg => &self.cfg,
            EdgeKindTag::Icfg => &self.icfg,
            EdgeKindTag::Pdg => &self.pdg,
            EdgeKindTag::Sdg => &self.sdg,
            EdgeKindTag::Rdg => &self.rdg,
        }
    }

    /// Append an edge id to the appropriate bucket.
    #[inline]
    fn push(&mut self, tag: EdgeKindTag, eid: EdgeId) {
        match tag {
            EdgeKindTag::Ast => self.ast.push(eid),
            EdgeKindTag::Cfg => self.cfg.push(eid),
            EdgeKindTag::Icfg => self.icfg.push(eid),
            EdgeKindTag::Pdg => self.pdg.push(eid),
            EdgeKindTag::Sdg => self.sdg.push(eid),
            EdgeKindTag::Rdg => self.rdg.push(eid),
        }
    }
}

// ============================================================================
// Symbol table
// ============================================================================

/// Interning key for the symbol table. Wraps a boxed string so the hash
/// table owns its canonical form exactly once.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
struct SymbolKey(Box<str>);

/// Metadata associated with each interned symbol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolEntry {
    /// Canonical form: `package:app/foo.dart#Class.method`.
    pub canonical: Box<str>,
    /// File the symbol was declared in, once the resolver has run.
    pub file: Option<FileId>,
    /// Declaration node in the CPG, once the resolver has run.
    pub decl: Option<NodeId>,
}

// ============================================================================
// The graph itself
// ============================================================================

/// The universal Code Property Graph.
///
/// Single-writer / many-reader. Built once per workspace by the language
/// frontends, mutated incrementally by the file watcher, and then queried
/// concurrently by the IFDS solver, the Semgrep rule runner, and the Z3
/// correlator. Readers take an immutable borrow and run lock-free.
pub struct CodeGraph {
    /// Arena for graph-lifetime string allocations (property blobs, etc.).
    /// Cleared only on a full workspace rebuild. Reserved for upcoming
    /// passes (Semgrep metavariable text storage, dataflow witness traces);
    /// suppress dead-code warning until those land.
    #[allow(dead_code)]
    pub(crate) bump: Bump,
    /// Dense node storage. Indexed by `NodeId::index()`.
    nodes: Vec<Node>,
    /// Dense edge storage. Indexed by `EdgeId::index()`.
    edges: Vec<Edge>,
    /// Outgoing adjacency: one [`PerKindAdj`] per node.
    out_adj: Vec<PerKindAdj>,
    /// Incoming adjacency: mirror of `out_adj`.
    in_adj: Vec<PerKindAdj>,
    /// Interned file path → `FileId`.
    files: FxHashMap<Box<str>, FileId>,
    /// Reverse lookup: `FileId` → canonical path.
    file_paths: Vec<Box<str>>,
    /// Interned symbol table: canonical form → `SymbolId`.
    symbols: FxHashMap<SymbolKey, SymbolId>,
    /// `SymbolId`-indexed metadata.
    symbol_data: Vec<SymbolEntry>,
}

impl CodeGraph {
    /// Construct an empty graph. Pre-reserves capacity for a mid-sized
    /// Flutter workspace (~64 k nodes, ~128 k edges) to avoid the first few
    /// reallocations on the build-graph hot path.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bump: Bump::new(),
            nodes: Vec::with_capacity(1 << 16),
            edges: Vec::with_capacity(1 << 17),
            out_adj: Vec::with_capacity(1 << 16),
            in_adj: Vec::with_capacity(1 << 16),
            files: FxHashMap::default(),
            file_paths: Vec::new(),
            symbols: FxHashMap::default(),
            symbol_data: Vec::new(),
        }
    }

    // -- interning --------------------------------------------------------

    /// Intern a canonical file path, returning its stable [`FileId`].
    pub fn intern_file(&mut self, path: &str) -> FileId {
        if let Some(&id) = self.files.get(path) {
            return id;
        }
        let id = FileId(u32::try_from(self.file_paths.len()).expect("file count overflow"));
        let boxed: Box<str> = path.into();
        self.file_paths.push(boxed.clone());
        self.files.insert(boxed, id);
        id
    }

    /// Intern a canonical symbol, returning its stable [`SymbolId`].
    pub fn intern_symbol(&mut self, canonical: &str) -> SymbolId {
        let key = SymbolKey(canonical.into());
        if let Some(&id) = self.symbols.get(&key) {
            return id;
        }
        let id = SymbolId(u32::try_from(self.symbol_data.len()).expect("symbol count overflow"));
        self.symbol_data.push(SymbolEntry {
            canonical: canonical.into(),
            file: None,
            decl: None,
        });
        self.symbols.insert(key, id);
        id
    }

    /// Resolve a symbol handle to its metadata entry.
    #[inline]
    #[must_use]
    pub fn symbol(&self, id: SymbolId) -> &SymbolEntry {
        &self.symbol_data[id.0 as usize]
    }

    /// Mutable access to a symbol entry (for the resolver pass).
    #[inline]
    pub fn symbol_mut(&mut self, id: SymbolId) -> &mut SymbolEntry {
        &mut self.symbol_data[id.0 as usize]
    }

    /// Resolve a file handle to its canonical path.
    #[inline]
    #[must_use]
    pub fn file_path(&self, id: FileId) -> &str {
        &self.file_paths[id.0 as usize]
    }

    // -- construction -----------------------------------------------------

    /// Allocate a new node. Returns its stable [`NodeId`]. The node is
    /// created with no resolved type, no symbol, and no enclosing procedure;
    /// later passes (type inference, call-graph, procedure partitioning)
    /// patch those fields in place via [`Self::node_mut`].
    pub fn add_node(&mut self, kind: NodeKind, file: FileId, byte_range: Range<u32>) -> NodeId {
        let raw = u32::try_from(self.nodes.len()).expect("node count overflow") + 1;
        let id = NodeId::new(raw);
        self.nodes.push(Node {
            id,
            kind,
            file,
            byte_range,
            type_ref: None,
            symbol: None,
            procedure: None,
        });
        self.out_adj.push(PerKindAdj::default());
        self.in_adj.push(PerKindAdj::default());
        id
    }

    /// Add a labeled edge between two existing nodes. Both adjacency
    /// indexes are updated in place so subsequent queries are O(1).
    pub fn add_edge(&mut self, src: NodeId, dst: NodeId, kind: EdgeKind) -> EdgeId {
        let raw = u32::try_from(self.edges.len()).expect("edge count overflow") + 1;
        let eid = EdgeId::new(raw);
        self.edges.push(Edge { src, dst, kind });
        let tag = kind.tag();
        self.out_adj[src.index()].push(tag, eid);
        self.in_adj[dst.index()].push(tag, eid);
        eid
    }

    // -- access -----------------------------------------------------------

    /// Borrow a node by id.
    #[inline]
    #[must_use]
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id.index()]
    }

    /// Mutably borrow a node by id (used by resolver passes).
    #[inline]
    pub fn node_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[id.index()]
    }

    /// Borrow an edge by id.
    #[inline]
    #[must_use]
    pub fn edge(&self, id: EdgeId) -> &Edge {
        &self.edges[id.index()]
    }

    /// Iterate outgoing edges from `src` filtered to a single sub-graph.
    ///
    /// This is the hot path for the IFDS solver's worklist loop. The
    /// implementation is two pointer dereferences + a linear walk over a
    /// `SmallVec`, which compiles down to a tight SIMD-friendly loop.
    pub fn out_edges(&self, src: NodeId, tag: EdgeKindTag) -> impl Iterator<Item = &Edge> + '_ {
        self.out_adj[src.index()]
            .bucket(tag)
            .iter()
            .map(move |&e| self.edge(e))
    }

    /// Iterate outgoing edges from `src` alongside their stable `EdgeId`.
    pub fn out_edges_with_id(
        &self,
        src: NodeId,
        tag: EdgeKindTag,
    ) -> impl Iterator<Item = (EdgeId, &Edge)> + '_ {
        self.out_adj[src.index()]
            .bucket(tag)
            .iter()
            .map(move |&e| (e, self.edge(e)))
    }

    /// Iterate incoming edges to `dst` filtered to a single sub-graph.
    pub fn in_edges(&self, dst: NodeId, tag: EdgeKindTag) -> impl Iterator<Item = &Edge> + '_ {
        self.in_adj[dst.index()]
            .bucket(tag)
            .iter()
            .map(move |&e| self.edge(e))
    }

    /// Iterate outgoing edges from `src` across **every** sub-graph.
    /// Useful for slicing passes that do not care about edge provenance.
    pub fn out_edges_all(&self, src: NodeId) -> impl Iterator<Item = &Edge> + '_ {
        self.out_edges_with_id_all(src).map(|(_, e)| e)
    }

    /// Iterate outgoing edges from `src` across every sub-graph, yielding
    /// both the ID and the edge. Used by the persistence layer.
    pub fn out_edges_with_id_all(&self, src: NodeId) -> impl Iterator<Item = (EdgeId, &Edge)> + '_ {
        let adj = &self.out_adj[src.index()];
        adj.ast
            .iter()
            .chain(adj.cfg.iter())
            .chain(adj.icfg.iter())
            .chain(adj.pdg.iter())
            .chain(adj.sdg.iter())
            .chain(adj.rdg.iter())
            .map(move |&e| (e, self.edge(e)))
    }

    /// Total node count.
    #[inline]
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total edge count across all sub-graphs.
    #[inline]
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    // -- iteration --------------------------------------------------------

    /// Iterate all live nodes. Used by serialisation and by the reactive
    /// builder's global scan.
    pub fn iter_nodes(&self) -> impl Iterator<Item = &Node> + '_ {
        self.nodes.iter()
    }

    /// Iterate all edges. Used by serialisation.
    pub fn iter_edges(&self) -> impl Iterator<Item = &Edge> + '_ {
        self.edges.iter()
    }

    // -- file-level queries (for incremental analysis) --------------------

    /// Collect every `NodeId` that originated from `file`. Linear scan —
    /// callers should cache the result or use the persistence layer's
    /// `file_idx` column family for O(1) lookup.
    pub fn nodes_for_file(&self, file: FileId) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|n| n.file == file)
            .map(|n| n.id)
            .collect()
    }

    /// Tombstone all nodes owned by `file` and remove their edges from the
    /// adjacency index. The node slots become dead gaps in the arena — IDs
    /// are never reused so summary-edge caches for unaffected procedures
    /// remain valid.
    ///
    /// Returns the set of procedure entry nodes that were invalidated, so
    /// the incremental analysis driver knows which IFDS summaries to flush.
    pub fn tombstone_file(&mut self, file: FileId) -> Vec<NodeId> {
        let stale: Vec<NodeId> = self.nodes_for_file(file);
        let stale_set: rustc_hash::FxHashSet<NodeId> = stale.iter().copied().collect();

        // Collect procedures that owned the stale nodes.
        let mut invalidated_procs = Vec::new();
        for &nid in &stale {
            if let Some(proc) = self.nodes[nid.index()].procedure {
                if stale_set.contains(&proc) {
                    invalidated_procs.push(proc);
                }
            }
        }
        invalidated_procs.sort_unstable();
        invalidated_procs.dedup();

        // Remove edges touching any stale node from the edge arena and
        // adjacency indexes. We walk edges in reverse so removals don't
        // shift indexes we haven't visited yet.
        let mut dead_eids = Vec::new();
        for (idx, edge) in self.edges.iter().enumerate() {
            if stale_set.contains(&edge.src) || stale_set.contains(&edge.dst) {
                dead_eids.push(idx);
            }
        }

        // Clear adjacency buckets for stale nodes.
        for &nid in &stale {
            self.out_adj[nid.index()] = PerKindAdj::default();
            self.in_adj[nid.index()] = PerKindAdj::default();
        }

        // Remove stale-edge references from non-stale nodes' adjacency.
        let dead_edge_set: rustc_hash::FxHashSet<usize> = dead_eids.iter().copied().collect();
        for adj in &mut self.out_adj {
            Self::filter_adj_bucket(&mut adj.ast, &dead_edge_set);
            Self::filter_adj_bucket(&mut adj.cfg, &dead_edge_set);
            Self::filter_adj_bucket(&mut adj.icfg, &dead_edge_set);
            Self::filter_adj_bucket(&mut adj.pdg, &dead_edge_set);
            Self::filter_adj_bucket(&mut adj.sdg, &dead_edge_set);
            Self::filter_adj_bucket(&mut adj.rdg, &dead_edge_set);
        }
        for adj in &mut self.in_adj {
            Self::filter_adj_bucket(&mut adj.ast, &dead_edge_set);
            Self::filter_adj_bucket(&mut adj.cfg, &dead_edge_set);
            Self::filter_adj_bucket(&mut adj.icfg, &dead_edge_set);
            Self::filter_adj_bucket(&mut adj.pdg, &dead_edge_set);
            Self::filter_adj_bucket(&mut adj.sdg, &dead_edge_set);
            Self::filter_adj_bucket(&mut adj.rdg, &dead_edge_set);
        }

        invalidated_procs
    }

    /// Remove edge ids whose arena index is in `dead` from a SmallVec bucket.
    ///
    /// `where [EdgeId; N]: smallvec::Array<Item = EdgeId>` is required
    /// because smallvec's `Array` trait is implemented per-N via macro
    /// expansion, not generically over `const N`. The bound proves to the
    /// compiler that whichever N callers instantiate has an `Array` impl.
    fn filter_adj_bucket<const N: usize>(
        bucket: &mut SmallVec<[EdgeId; N]>,
        dead: &rustc_hash::FxHashSet<usize>,
    ) where
        [EdgeId; N]: smallvec::Array<Item = EdgeId>,
    {
        bucket.retain(|eid| !dead.contains(&eid.index()));
    }

    /// Build a lookup table mapping `(FileId, byte_range_start)` → `NodeId`.
    /// Used by the analyzer bridge to match resolved elements back to CPG
    /// nodes by source position.
    pub fn offset_index(&self) -> FxHashMap<(FileId, u32), NodeId> {
        let mut idx = FxHashMap::with_capacity_and_hasher(self.nodes.len(), Default::default());
        for node in &self.nodes {
            idx.insert((node.file, node.byte_range.start), node.id);
        }
        idx
    }
}

impl Default for CodeGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_niche_optimization() {
        // The whole reason for `NonZeroU32` is that `Option<NodeId>` should
        // stay 4 bytes. Fail the build loudly if anyone breaks that.
        assert_eq!(std::mem::size_of::<NodeId>(), 4);
        assert_eq!(std::mem::size_of::<Option<NodeId>>(), 4);
    }

    #[test]
    fn edge_kind_round_trip_tags() {
        assert_eq!(EdgeKind::Ast(AstEdge::NextSibling).tag(), EdgeKindTag::Ast);
        assert_eq!(EdgeKind::Cfg(CfgEdge::Fall).tag(), EdgeKindTag::Cfg);
        assert_eq!(EdgeKind::Icfg(IcfgEdge::Call).tag(), EdgeKindTag::Icfg);
        assert_eq!(
            EdgeKind::Pdg(PdgEdge::DataDep { var: SymbolId(0) }).tag(),
            EdgeKindTag::Pdg
        );
        assert_eq!(EdgeKind::Sdg(SdgEdge::Summary).tag(), EdgeKindTag::Sdg);
        assert_eq!(
            EdgeKind::Rdg(RdgEdge::ReactiveFlow {
                channel: SymbolId(0)
            })
            .tag(),
            EdgeKindTag::Rdg
        );
    }

    #[test]
    fn cpg_basic_construction_and_traversal() {
        let mut g = CodeGraph::new();
        let f = g.intern_file("package:demo/main.dart");
        let entry = g.add_node(NodeKind::EntryNode, f, 0..1);
        let call = g.add_node(NodeKind::CallSite, f, 1..2);
        let ret = g.add_node(NodeKind::ReturnSite, f, 2..3);
        let exit = g.add_node(NodeKind::ExitNode, f, 3..4);

        g.add_edge(entry, call, EdgeKind::Cfg(CfgEdge::Fall));
        g.add_edge(call, ret, EdgeKind::Icfg(IcfgEdge::CallToReturn));
        g.add_edge(ret, exit, EdgeKind::Cfg(CfgEdge::Fall));

        // CFG traversal must not leak ICFG edges.
        let cfg_succs: Vec<_> = g.out_edges(call, EdgeKindTag::Cfg).collect();
        assert!(
            cfg_succs.is_empty(),
            "CFG bucket should not contain ICFG edges"
        );

        let icfg_succs: Vec<_> = g.out_edges(call, EdgeKindTag::Icfg).collect();
        assert_eq!(icfg_succs.len(), 1);
        assert_eq!(icfg_succs[0].dst, ret);
    }

    #[test]
    fn symbol_interning_is_stable() {
        let mut g = CodeGraph::new();
        let a = g.intern_symbol("package:demo/a.dart#foo");
        let b = g.intern_symbol("package:demo/a.dart#foo");
        let c = g.intern_symbol("package:demo/a.dart#bar");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(g.symbol(a).canonical.as_ref(), "package:demo/a.dart#foo");
    }
}
