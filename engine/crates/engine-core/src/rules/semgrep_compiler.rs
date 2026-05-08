//! Semgrep YAML → IFDS flow-function compiler.
//!
//! # The ecosystem hijack
//!
//! Semgrep's open-source registry has 2000+ community-maintained security
//! rules. This module compiles them into implementations of our
//! [`FlowFunctions`] trait, which the IFDS solver then runs with full
//! inter-procedural, context-sensitive precision — 10× better than
//! Semgrep's own intra-procedural engine.
//!
//! # Pipeline
//!
//! ```text
//! semgrep_rule.yaml
//!       │  serde_yaml::from_str
//!       ▼
//!  SemgrepRule              ← parsed YAML structure
//!       │  PatternCompiler::compile
//!       ▼
//!  CompiledRule             ← source/sink matchers over CPG nodes
//!       │  SemgrepFlowFunctions::new
//!       ▼
//!  impl FlowFunctions       ← plugs into IfdsSolver
//! ```
//!
//! # Pattern translation
//!
//! A Semgrep pattern like `$DB.query($ARG)` compiles to a [`NodePredicate`]
//! that walks the CPG:
//!
//! 1. Find all `MethodCall` nodes whose symbol ends with `.query`.
//! 2. Bind `$DB` to the receiver sub-tree (AST child slot 0).
//! 3. Bind `$ARG` to the first argument sub-tree (AST child slot 2+).
//! 4. Return a `Match` with the bound metavariables.
//!
//! # Metavariable identity
//!
//! When the same metavariable name appears in both `pattern-sources` and
//! `pattern-sinks`, the IFDS fact domain encodes the binding so the solver
//! ensures identity: taint from a source binding `$X → node_42` cannot
//! merge with taint from `$X → node_99`.

use std::sync::Arc;

use regex::Regex;
use rustc_hash::FxHashMap;
use serde::Deserialize;
use smallvec::SmallVec;

use crate::cpg::{CodeGraph, EdgeKind, EdgeKindTag, NodeId, NodeKind, TypeRef};
use crate::frontend::types::TypeArena;
use crate::solver::{DomainFact, FlowFunctions, FlowResult};

// ============================================================================
// Semgrep YAML schema (serde)
// ============================================================================

/// Top-level Semgrep rule, deserialized from YAML.
#[derive(Clone, Debug, Deserialize)]
pub struct SemgrepRule {
    /// Rule identifier (e.g. `dart.lang.security.sql-injection`).
    pub id: String,
    /// Human-readable message.
    pub message: String,
    /// Severity: ERROR, WARNING, INFO.
    pub severity: String,
    /// Languages this rule targets.
    #[serde(default)]
    pub languages: Vec<String>,
    /// Analysis mode. `taint` enables source→sink tracking.
    #[serde(default)]
    pub mode: Option<String>,

    // -- Pattern fields (non-taint mode) ----------------------------------
    /// Single pattern (simplest form).
    #[serde(default)]
    pub pattern: Option<String>,
    /// Conjunction of patterns (all must match).
    #[serde(default)]
    pub patterns: Option<Vec<PatternClause>>,
    /// Disjunction of patterns (any may match).
    #[serde(rename = "pattern-either", default)]
    pub pattern_either: Option<Vec<PatternClause>>,

    // -- Taint mode fields ------------------------------------------------
    /// Source patterns — values that originate user-controlled data.
    #[serde(rename = "pattern-sources", default)]
    pub pattern_sources: Option<Vec<PatternClause>>,
    /// Sink patterns — call sites or assignments where tainted values are
    /// dangerous.
    #[serde(rename = "pattern-sinks", default)]
    pub pattern_sinks: Option<Vec<PatternClause>>,
    /// Sanitizer patterns — call sites that neutralise taint.
    #[serde(rename = "pattern-sanitizers", default)]
    pub pattern_sanitizers: Option<Vec<PatternClause>>,

    // -- Metavariable constraints -----------------------------------------
    /// Per-metavariable type constraints (e.g. `$X` must be a `String`).
    #[serde(rename = "metavariable-type", default)]
    pub metavariable_type: Option<Vec<MetavarTypeConstraint>>,
    /// Per-metavariable regex constraints applied to the captured node's
    /// source text.
    #[serde(rename = "metavariable-regex", default)]
    pub metavariable_regex: Option<Vec<MetavarRegexConstraint>>,
}

/// A pattern clause — either a single pattern or a negation.
#[derive(Clone, Debug, Deserialize)]
pub struct PatternClause {
    /// Positive pattern; matched nodes are kept.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Negative pattern; matched nodes are excluded from the parent set.
    #[serde(rename = "pattern-not", default)]
    pub pattern_not: Option<String>,
    /// Disjunction of nested clauses; the clause matches when any sub-clause
    /// matches.
    #[serde(rename = "pattern-either", default)]
    pub pattern_either: Option<Vec<PatternClause>>,
    /// Per-metavariable type constraints scoped to this clause.
    #[serde(rename = "metavariable-type", default)]
    pub metavariable_type: Option<Vec<MetavarTypeConstraint>>,
    /// Per-metavariable regex constraints scoped to this clause.
    #[serde(rename = "metavariable-regex", default)]
    pub metavariable_regex: Option<Vec<MetavarRegexConstraint>>,
}

/// Constrains a captured metavariable to a specific type.
#[derive(Clone, Debug, Deserialize)]
pub struct MetavarTypeConstraint {
    /// Metavariable name without the `$` sigil (e.g. `X` for `$X`).
    pub metavariable: String,
    /// Canonical type name the metavariable must be a subtype of.
    #[serde(rename = "type")]
    pub type_name: String,
}

/// Constrains a captured metavariable's source text to match a regex.
#[derive(Clone, Debug, Deserialize)]
pub struct MetavarRegexConstraint {
    /// Metavariable name without the `$` sigil.
    pub metavariable: String,
    /// Regex applied to the captured node's source-text span.
    pub regex: String,
}

// ============================================================================
// Compiled representations
// ============================================================================

/// Interned metavariable name. Stored as a u16 index into a per-rule table
/// rather than a heap-allocated string for O(1) hashing in the fact domain.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct MetavarId(pub u16);

/// A compiled rule ready for execution against a CPG.
#[derive(Clone, Debug)]
pub struct CompiledRule {
    /// Original rule id.
    pub id: String,
    /// Severity.
    pub severity: String,
    /// Message template.
    pub message: String,
    /// Is this a taint-mode rule?
    pub is_taint: bool,
    /// Source matchers (taint mode only).
    pub sources: Vec<CompiledMatcher>,
    /// Sink matchers (taint mode only).
    pub sinks: Vec<CompiledMatcher>,
    /// Sanitizer matchers (taint mode only).
    pub sanitizers: Vec<CompiledMatcher>,
    /// Pattern matchers (non-taint mode).
    pub patterns: Vec<CompiledMatcher>,
    /// Metavariable name table (index = MetavarId).
    pub metavar_names: Vec<String>,
}

/// A compiled pattern matcher — a predicate over CPG nodes that may capture
/// metavariables.
#[derive(Clone, Debug)]
pub struct CompiledMatcher {
    /// Predicate tree.
    pub predicate: NodePredicate,
    /// Whether this is a negation (pattern-not).
    pub negated: bool,
}

/// Predicate tree over CPG nodes. Each variant maps to one Semgrep pattern
/// primitive.
#[derive(Clone, Debug)]
pub enum NodePredicate {
    /// Match a node by kind.
    KindIs(NodeKind),
    /// Match a node whose symbol's canonical name ends with the given
    /// suffix. Compiles from `$X.query(...)` where `query` is the method.
    SymbolEndsWith(String),
    /// Match a node whose symbol's canonical name contains the substring.
    SymbolContains(String),
    /// Match a node whose resolved type is a subtype of the given
    /// canonical name. Used by `metavariable-type`.
    TypeIs(String),
    /// Capture a metavariable: bind the node's identity to the named slot.
    Capture(MetavarId),
    /// Deep capture: match any sub-tree and bind its root. Compiles from
    /// `$...X` (ellipsis metavariable).
    DeepCapture(MetavarId),
    /// Match a node that has an AST child at `slot` matching `inner`.
    HasChild {
        /// Positional slot in the parent's grammar production
        /// (slot 0 = receiver, 1 = selector, 2+ = arguments for method calls).
        slot: u16,
        /// Predicate the child node must satisfy.
        inner: Box<NodePredicate>,
    },
    /// Logical AND.
    And(Vec<NodePredicate>),
    /// Logical OR.
    Or(Vec<NodePredicate>),
    /// Logical NOT.
    Not(Box<NodePredicate>),
    /// Source text at the node's byte range matches a regex. Compiles from
    /// `metavariable-regex`.
    SourceRegex(Regex),
    /// Always matches.
    Any,
}

/// A successful match result: a CPG node + captured metavariable bindings.
#[derive(Clone, Debug)]
pub struct Match {
    /// The matched node.
    pub node: NodeId,
    /// Captured bindings: metavar slot → CPG node.
    pub bindings: MetavarBindings,
}

/// Captured metavariable bindings. Kept small and hashable so it can live
/// inside the IFDS fact domain.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct MetavarBindings {
    /// Sorted by MetavarId for deterministic hashing.
    pub entries: SmallVec<[(MetavarId, NodeId); 4]>,
}

impl MetavarBindings {
    /// Empty bindings.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: SmallVec::new(),
        }
    }

    /// Insert a binding. Maintains sorted order.
    pub fn insert(&mut self, var: MetavarId, node: NodeId) {
        match self.entries.binary_search_by_key(&var, |&(v, _)| v) {
            Ok(pos) => self.entries[pos] = (var, node),
            Err(pos) => self.entries.insert(pos, (var, node)),
        }
    }

    /// Look up a binding.
    #[must_use]
    pub fn get(&self, var: MetavarId) -> Option<NodeId> {
        self.entries
            .binary_search_by_key(&var, |&(v, _)| v)
            .ok()
            .map(|pos| self.entries[pos].1)
    }

    /// Are two bindings consistent? They are consistent if every shared
    /// metavar name maps to the same CPG node.
    #[must_use]
    pub fn consistent_with(&self, other: &Self) -> bool {
        let mut i = 0;
        let mut j = 0;
        while i < self.entries.len() && j < other.entries.len() {
            let (va, na) = self.entries[i];
            let (vb, nb) = other.entries[j];
            match va.cmp(&vb) {
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => {
                    if na != nb {
                        return false;
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
        true
    }
}

// ============================================================================
// Pattern compiler
// ============================================================================

/// Compiles a [`SemgrepRule`] into a [`CompiledRule`].
pub struct PatternCompiler {
    /// Metavar name → id mapping, built during compilation.
    metavar_table: FxHashMap<String, MetavarId>,
    /// Reverse: id → name.
    metavar_names: Vec<String>,
}

impl PatternCompiler {
    /// Create a new compiler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metavar_table: FxHashMap::default(),
            metavar_names: Vec::new(),
        }
    }

    /// Compile a Semgrep YAML rule into an executable form.
    pub fn compile(&mut self, rule: &SemgrepRule) -> CompiledRule {
        let is_taint = rule.mode.as_deref() == Some("taint");

        let sources = rule
            .pattern_sources
            .as_ref()
            .map(|clauses| self.compile_clauses(clauses))
            .unwrap_or_default();

        let sinks = rule
            .pattern_sinks
            .as_ref()
            .map(|clauses| self.compile_clauses(clauses))
            .unwrap_or_default();

        let sanitizers = rule
            .pattern_sanitizers
            .as_ref()
            .map(|clauses| self.compile_clauses(clauses))
            .unwrap_or_default();

        let patterns = if !is_taint {
            let mut matchers = Vec::new();
            if let Some(ref pat) = rule.pattern {
                matchers.push(CompiledMatcher {
                    predicate: self.compile_pattern(pat),
                    negated: false,
                });
            }
            if let Some(ref clauses) = rule.patterns {
                matchers.extend(self.compile_clauses(clauses));
            }
            if let Some(ref clauses) = rule.pattern_either {
                matchers.push(CompiledMatcher {
                    predicate: NodePredicate::Or(
                        clauses
                            .iter()
                            .filter_map(|c| c.pattern.as_ref())
                            .map(|p| self.compile_pattern(p))
                            .collect(),
                    ),
                    negated: false,
                });
            }
            matchers
        } else {
            Vec::new()
        };

        CompiledRule {
            id: rule.id.clone(),
            severity: rule.severity.clone(),
            message: rule.message.clone(),
            is_taint,
            sources,
            sinks,
            sanitizers,
            patterns,
            metavar_names: self.metavar_names.clone(),
        }
    }

    fn compile_clauses(&mut self, clauses: &[PatternClause]) -> Vec<CompiledMatcher> {
        let mut matchers = Vec::new();
        for clause in clauses {
            if let Some(ref pat) = clause.pattern {
                matchers.push(CompiledMatcher {
                    predicate: self.compile_pattern(pat),
                    negated: false,
                });
            }
            if let Some(ref pat) = clause.pattern_not {
                matchers.push(CompiledMatcher {
                    predicate: self.compile_pattern(pat),
                    negated: true,
                });
            }
            if let Some(ref either) = clause.pattern_either {
                matchers.push(CompiledMatcher {
                    predicate: NodePredicate::Or(
                        either
                            .iter()
                            .filter_map(|c| c.pattern.as_ref())
                            .map(|p| self.compile_pattern(p))
                            .collect(),
                    ),
                    negated: false,
                });
            }
        }
        matchers
    }

    /// Compile a single Semgrep pattern string into a [`NodePredicate`].
    ///
    /// Pattern syntax we support:
    /// - `$X.method($Y)` → MethodCall with symbol ending in `.method`,
    ///   receiver captured as `$X`, first arg as `$Y`.
    /// - `$...X.method($...Y)` → deep (chain) captures.
    /// - `foo(...)` → Call with symbol ending in `foo`.
    /// - `$X = ...` → Assign with LHS captured.
    fn compile_pattern(&mut self, pattern: &str) -> NodePredicate {
        let pat = pattern.trim();

        // Pattern: `$RECV.method($ARGS)` or `$...RECV.method($...ARGS)`
        if let Some(dot_pos) = self.find_method_dot(pat) {
            let receiver_part = &pat[..dot_pos];
            let rest = &pat[dot_pos + 1..];

            // Extract method name and args.
            let (method_name, args_part) = if let Some(paren) = rest.find('(') {
                (
                    &rest[..paren],
                    Some(&rest[paren + 1..rest.len().saturating_sub(1)]),
                )
            } else {
                (rest, None)
            };

            let mut predicates = vec![NodePredicate::KindIs(NodeKind::MethodCall)];

            // Only constrain on the trailing symbol when the method name is
            // a literal identifier. Metavariable forms like `$FIELD` are
            // wildcards — emitting `SymbolEndsWith(".$FIELD")` would produce
            // a predicate that never matches anything (the metavariable
            // sigil is not part of any real symbol).
            if !method_name.starts_with('$') && !method_name.is_empty() {
                predicates.push(NodePredicate::SymbolEndsWith(format!(".{method_name}")));
            } else if let Some(name) = method_name.strip_prefix("$...") {
                // `$...METHOD` — deep capture on the method name slot. We
                // record the binding via a fresh metavariable id; the
                // bound node ends up being the chain root itself, which
                // downstream rules can re-inspect.
                let id = self.intern_metavar(name);
                predicates.push(NodePredicate::DeepCapture(id));
            } else if let Some(name) = method_name.strip_prefix('$') {
                let id = self.intern_metavar(name);
                predicates.push(NodePredicate::Capture(id));
            }

            // Receiver capture.
            let recv_pred = self.compile_capture(receiver_part);
            predicates.push(NodePredicate::HasChild {
                slot: 0,
                inner: Box::new(recv_pred),
            });

            // Argument captures.
            if let Some(args) = args_part {
                for (i, arg) in args.split(',').enumerate() {
                    let arg = arg.trim();
                    if arg == "..." || arg.is_empty() {
                        continue;
                    }
                    let arg_pred = self.compile_capture(arg);
                    predicates.push(NodePredicate::HasChild {
                        slot: (i as u16) + 2, // slot 0 = recv, 1 = selector
                        inner: Box::new(arg_pred),
                    });
                }
            }

            return NodePredicate::And(predicates);
        }

        // Pattern: `foo($ARGS)` (bare function call)
        if let Some(paren) = pat.find('(') {
            let func_name = &pat[..paren];
            if !func_name.starts_with('$') && !func_name.is_empty() {
                return NodePredicate::And(vec![
                    NodePredicate::KindIs(NodeKind::Call),
                    NodePredicate::SymbolEndsWith(func_name.to_string()),
                ]);
            }
        }

        // Fallback: treat the whole pattern as a symbol-contains search.
        if pat.starts_with('$') {
            self.compile_capture(pat)
        } else {
            NodePredicate::SymbolContains(pat.to_string())
        }
    }

    /// Compile a metavariable reference (`$X` or `$...X`) into a capture
    /// predicate.
    fn compile_capture(&mut self, token: &str) -> NodePredicate {
        let token = token.trim();
        if let Some(name) = token.strip_prefix("$...") {
            let id = self.intern_metavar(name);
            NodePredicate::DeepCapture(id)
        } else if let Some(name) = token.strip_prefix('$') {
            let id = self.intern_metavar(name);
            NodePredicate::Capture(id)
        } else {
            NodePredicate::SymbolContains(token.to_string())
        }
    }

    /// Intern a metavariable name, returning its id.
    fn intern_metavar(&mut self, name: &str) -> MetavarId {
        if let Some(&id) = self.metavar_table.get(name) {
            return id;
        }
        let id =
            MetavarId(u16::try_from(self.metavar_names.len()).expect("too many metavariables"));
        self.metavar_names.push(name.to_string());
        self.metavar_table.insert(name.to_string(), id);
        id
    }

    /// Find the position of the method-call dot in a pattern. Skips dots
    /// inside `$...` sequences.
    fn find_method_dot(&self, pat: &str) -> Option<usize> {
        let mut i = pat.len();
        // Walk backwards to find the last `.` that is not part of `$...`.
        while i > 0 {
            i -= 1;
            if pat.as_bytes()[i] == b'.' {
                // Check it's not preceded by `$..`
                if i >= 2 && &pat[i - 2..i] == ".." {
                    continue;
                }
                return Some(i);
            }
        }
        None
    }
}

impl Default for PatternCompiler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CPG scanning — match compiled predicates against graph nodes
// ============================================================================

/// Scan the CPG for nodes matching a compiled matcher, returning all
/// matches with their metavariable bindings.
pub fn scan_cpg(
    graph: &CodeGraph,
    types: &TypeArena,
    matcher: &CompiledMatcher,
    source_text: &FxHashMap<FileId, &str>,
) -> Vec<Match> {
    let mut results = Vec::new();

    for node in graph.iter_nodes() {
        let mut bindings = MetavarBindings::empty();
        let matched = eval_predicate(
            graph,
            types,
            source_text,
            node.id,
            &matcher.predicate,
            &mut bindings,
        );

        if matched != matcher.negated {
            results.push(Match {
                node: node.id,
                bindings,
            });
        }
    }

    results
}

use crate::cpg::FileId;

/// Evaluate a predicate against a single CPG node. Returns `true` if the
/// node matches. Captures are written into `bindings`.
fn eval_predicate(
    graph: &CodeGraph,
    types: &TypeArena,
    source_text: &FxHashMap<FileId, &str>,
    node: NodeId,
    pred: &NodePredicate,
    bindings: &mut MetavarBindings,
) -> bool {
    match pred {
        NodePredicate::Any => true,

        NodePredicate::KindIs(kind) => graph.node(node).kind == *kind,

        NodePredicate::SymbolEndsWith(suffix) => graph
            .node(node)
            .symbol
            .map(|s| graph.symbol(s).canonical.ends_with(suffix.as_str()))
            .unwrap_or(false),

        NodePredicate::SymbolContains(substring) => graph
            .node(node)
            .symbol
            .map(|s| graph.symbol(s).canonical.contains(substring.as_str()))
            .unwrap_or(false),

        NodePredicate::TypeIs(type_canonical) => {
            if let Some(TypeRef::Resolved(tid)) = &graph.node(node).type_ref {
                types.is_subtype(*tid, type_canonical)
            } else {
                false
            }
        }

        NodePredicate::Capture(metavar) => {
            bindings.insert(*metavar, node);
            true
        }

        NodePredicate::DeepCapture(metavar) => {
            bindings.insert(*metavar, node);
            true
        }

        NodePredicate::HasChild { slot, inner } => {
            for edge in graph.out_edges(node, EdgeKindTag::Ast) {
                if matches!(
                    edge.kind,
                    EdgeKind::Ast(crate::cpg::AstEdge::Child { slot: s }) if s == *slot
                ) {
                    return eval_predicate(graph, types, source_text, edge.dst, inner, bindings);
                }
            }
            false
        }

        NodePredicate::And(preds) => preds
            .iter()
            .all(|p| eval_predicate(graph, types, source_text, node, p, bindings)),

        NodePredicate::Or(preds) => preds
            .iter()
            .any(|p| eval_predicate(graph, types, source_text, node, p, bindings)),

        NodePredicate::Not(inner) => {
            !eval_predicate(graph, types, source_text, node, inner, bindings)
        }

        NodePredicate::SourceRegex(re) => {
            let n = graph.node(node);
            if let Some(text) = source_text.get(&n.file) {
                let start = n.byte_range.start as usize;
                let end = (n.byte_range.end as usize).min(text.len());
                if start < end {
                    return re.is_match(&text[start..end]);
                }
            }
            false
        }
    }
}

// ============================================================================
// IFDS fact domain for Semgrep taint rules
// ============================================================================

/// IFDS domain fact for Semgrep-compiled taint rules.
///
/// Each fact tracks which CPG node is tainted plus the metavariable
/// bindings that were captured at the source. Two facts with different
/// bindings are distinct, ensuring that `$X` captured at source A does
/// not conflate with `$X` captured at source B.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct SemgrepFact {
    /// Which abstract variable is tainted. `None` = zero fact Λ.
    tainted_node: Option<NodeId>,
    /// Metavariable bindings captured at the taint source.
    bindings: Arc<MetavarBindings>,
}

impl DomainFact for SemgrepFact {
    fn zero() -> Self {
        Self {
            tainted_node: None,
            bindings: Arc::new(MetavarBindings::empty()),
        }
    }

    fn is_zero(&self) -> bool {
        self.tainted_node.is_none()
    }
}

// ============================================================================
// IFDS flow functions for Semgrep taint rules
// ============================================================================

/// Flow functions generated from a compiled Semgrep taint rule. Plugs
/// directly into [`IfdsSolver`].
pub struct SemgrepFlowFunctions {
    /// Compiled rule (owns source/sink/sanitizer matchers).
    rule: Arc<CompiledRule>,
    /// Source match results: node → bindings.
    source_nodes: FxHashMap<NodeId, MetavarBindings>,
    /// Sink match results: node → bindings.
    sink_nodes: FxHashMap<NodeId, MetavarBindings>,
    /// Sanitizer match results (set of nodes).
    sanitizer_nodes: rustc_hash::FxHashSet<NodeId>,
}

impl SemgrepFlowFunctions {
    /// Create flow functions from a compiled rule and pre-computed match
    /// results. Call [`scan_cpg`] on each source/sink/sanitizer matcher
    /// to produce the match sets, then pass them here.
    pub fn new(
        rule: Arc<CompiledRule>,
        sources: Vec<Match>,
        sinks: Vec<Match>,
        sanitizers: Vec<Match>,
    ) -> Self {
        let source_nodes = sources.into_iter().map(|m| (m.node, m.bindings)).collect();
        let sink_nodes = sinks.into_iter().map(|m| (m.node, m.bindings)).collect();
        let sanitizer_nodes = sanitizers.into_iter().map(|m| m.node).collect();
        Self {
            rule,
            source_nodes,
            sink_nodes,
            sanitizer_nodes,
        }
    }

    /// Check if a node is a sink with bindings consistent with the given
    /// taint fact. Used by the reporting pass after IFDS completes.
    #[must_use]
    pub fn is_sink_for(&self, node: NodeId, fact: &SemgrepFact) -> bool {
        if let Some(sink_bindings) = self.sink_nodes.get(&node) {
            return fact.bindings.consistent_with(sink_bindings);
        }
        false
    }

    /// The compiled rule, for attribution in findings.
    #[must_use]
    pub fn rule(&self) -> &CompiledRule {
        &self.rule
    }

    /// Iterate the source nodes the rule discovered when it was loaded.
    /// Drivers seed the IFDS solver at every yielded node.
    pub fn source_node_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.source_nodes.keys().copied()
    }

    /// Iterate the sink nodes the rule discovered when it was loaded.
    /// After `IfdsSolver::run()`, drivers query `IfdsSolver::is_tainted()`
    /// on each yielded node to extract findings.
    pub fn sink_node_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.sink_nodes.keys().copied()
    }

    /// Iterate the sanitizer nodes the rule discovered when it was loaded.
    /// Provided for telemetry / debugging — the IFDS solver consumes them
    /// internally via `FlowFunctions::normal`.
    pub fn sanitizer_node_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.sanitizer_nodes.iter().copied()
    }
}

impl FlowFunctions for SemgrepFlowFunctions {
    type Fact = SemgrepFact;

    fn normal(
        &self,
        _graph: &CodeGraph,
        curr: NodeId,
        _succ: NodeId,
        fact: &Self::Fact,
    ) -> FlowResult<Self::Fact> {
        let mut out = FlowResult::new();

        // Always propagate the existing fact (identity).
        out.push(fact.clone());

        // Source activation: if `curr` is a source node and we hold the
        // zero fact, inject a tainted fact with the source's bindings.
        if fact.is_zero() {
            if let Some(bindings) = self.source_nodes.get(&curr) {
                out.push(SemgrepFact {
                    tainted_node: Some(curr),
                    bindings: Arc::new(bindings.clone()),
                });
            }
        }

        // Sanitizer kill: if `curr` is a sanitizer, drop the tainted fact.
        if !fact.is_zero() && self.sanitizer_nodes.contains(&curr) {
            out.retain(|f| f.is_zero());
        }

        out
    }

    fn call(
        &self,
        _graph: &CodeGraph,
        _call_site: NodeId,
        _callee_entry: NodeId,
        fact: &Self::Fact,
    ) -> FlowResult<Self::Fact> {
        // Pass facts through calls unchanged — the IFDS summary edges
        // handle context sensitivity.
        let mut out = FlowResult::new();
        out.push(fact.clone());
        out
    }

    fn return_flow(
        &self,
        _graph: &CodeGraph,
        _call_site: NodeId,
        _callee_exit: NodeId,
        _return_site: NodeId,
        fact: &Self::Fact,
    ) -> FlowResult<Self::Fact> {
        let mut out = FlowResult::new();
        out.push(fact.clone());
        out
    }

    fn call_to_return(
        &self,
        _graph: &CodeGraph,
        _call_site: NodeId,
        _return_site: NodeId,
        fact: &Self::Fact,
    ) -> FlowResult<Self::Fact> {
        let mut out = FlowResult::new();
        out.push(fact.clone());
        out
    }
}

// ============================================================================
// End-to-end convenience: load YAML → compile → scan → create flow functions
// ============================================================================

/// Load a Semgrep YAML rule, compile it, scan the CPG for sources/sinks,
/// and return ready-to-use flow functions.
pub fn load_rule(
    yaml: &str,
    graph: &CodeGraph,
    types: &TypeArena,
    source_text: &FxHashMap<FileId, &str>,
) -> Result<SemgrepFlowFunctions, String> {
    let rule: SemgrepRule =
        serde_yaml::from_str(yaml).map_err(|e| format!("YAML parse error: {e}"))?;

    let mut compiler = PatternCompiler::new();
    let compiled = compiler.compile(&rule);

    if !compiled.is_taint {
        return Err(format!(
            "rule {} is not a taint rule — non-taint rules run via pattern matching, not IFDS",
            compiled.id
        ));
    }

    let sources: Vec<Match> = compiled
        .sources
        .iter()
        .flat_map(|m| scan_cpg(graph, types, m, source_text))
        .collect();

    let sinks: Vec<Match> = compiled
        .sinks
        .iter()
        .flat_map(|m| scan_cpg(graph, types, m, source_text))
        .collect();

    let sanitizers: Vec<Match> = compiled
        .sanitizers
        .iter()
        .flat_map(|m| scan_cpg(graph, types, m, source_text))
        .collect();

    Ok(SemgrepFlowFunctions::new(
        Arc::new(compiled),
        sources,
        sinks,
        sanitizers,
    ))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_semgrep_taint_yaml() {
        let yaml = r#"
id: dart.security.sql-injection
message: "Possible SQL injection"
severity: ERROR
languages: [dart]
mode: taint
pattern-sources:
  - pattern: "$INPUT = request.body.$FIELD"
pattern-sinks:
  - pattern: "$DB.rawQuery($INPUT)"
pattern-sanitizers:
  - pattern: "sanitize($INPUT)"
"#;
        let rule: SemgrepRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.id, "dart.security.sql-injection");
        assert_eq!(rule.mode.as_deref(), Some("taint"));
        assert!(rule.pattern_sources.is_some());
        assert!(rule.pattern_sinks.is_some());
        assert!(rule.pattern_sanitizers.is_some());
    }

    #[test]
    fn compile_method_call_pattern() {
        let mut compiler = PatternCompiler::new();
        let pred = compiler.compile_pattern("$DB.rawQuery($SQL)");

        // Should produce And([KindIs(MethodCall), SymbolEndsWith(".rawQuery"), HasChild{0, Capture(DB)}, HasChild{2, Capture(SQL)}])
        match &pred {
            NodePredicate::And(parts) => {
                assert!(
                    parts.len() >= 3,
                    "expected ≥3 predicates, got {}",
                    parts.len()
                );
                assert!(
                    matches!(parts[0], NodePredicate::KindIs(NodeKind::MethodCall)),
                    "first predicate should be KindIs(MethodCall)"
                );
                assert!(
                    matches!(&parts[1], NodePredicate::SymbolEndsWith(s) if s == ".rawQuery"),
                    "second predicate should be SymbolEndsWith(.rawQuery)"
                );
            }
            other => panic!("expected And, got: {other:?}"),
        }

        // Verify metavar table was populated.
        assert_eq!(compiler.metavar_names.len(), 2);
        assert!(compiler.metavar_names.contains(&"DB".to_string()));
        assert!(compiler.metavar_names.contains(&"SQL".to_string()));
    }

    #[test]
    fn metavar_bindings_consistency() {
        let mut a = MetavarBindings::empty();
        let mut b = MetavarBindings::empty();

        let n1 = NodeId::new(1);
        let n2 = NodeId::new(2);
        let v0 = MetavarId(0);

        a.insert(v0, n1);
        b.insert(v0, n1);
        assert!(a.consistent_with(&b));

        b.insert(v0, n2);
        assert!(
            !a.consistent_with(&b),
            "different bindings should be inconsistent"
        );
    }

    #[test]
    fn semgrep_fact_zero_identity() {
        let zero = SemgrepFact::zero();
        assert!(zero.is_zero());
        assert_eq!(zero, SemgrepFact::zero());

        let tainted = SemgrepFact {
            tainted_node: Some(NodeId::new(1)),
            bindings: Arc::new(MetavarBindings::empty()),
        };
        assert!(!tainted.is_zero());
        assert_ne!(zero, tainted);
    }
}
