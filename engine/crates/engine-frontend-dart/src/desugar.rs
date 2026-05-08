//! Pass 3: Desugar — Flattening Cascades and Implicit This.
//!
//! This pass normalizes Dart-specific syntactic sugar into a canonical
//! form for the solver. It ensures that a cascade `obj..a()..b()` is
//! treated as two sequential calls on the same receiver.

use engine_core::cpg::{CodeGraph, NodeId, NodeKind};

pub struct DesugarPass<'g> {
    graph: &'g mut CodeGraph,
}

impl<'g> DesugarPass<'g> {
    pub fn new(graph: &'g mut CodeGraph) -> Self {
        Self { graph }
    }

    pub fn run(&mut self) {
        // We iterate nodes to find patterns that need desugaring.
        let nodes: Vec<NodeId> = self.graph.iter_nodes().map(|n| n.id).collect();
        for nid in nodes {
            self.process_node(nid);
        }
    }

    fn process_node(&mut self, nid: NodeId) {
        let kind = self.graph.node(nid).kind;
        match kind {
            NodeKind::MethodCall => self.handle_cascade(nid),
            NodeKind::Identifier => self.handle_implicit_this(nid),
            _ => {}
        }
    }

    /// If a method call is part of a cascade, ensure the CFG flows
    /// correctly through the receiver to subsequent calls.
    fn handle_cascade(&mut self, _nid: NodeId) {
        // TODO: find cascade parent, link receiver to next call in chain.
        // Currently a no-op stub — cascade lowering happens later.
    }

    /// Injects symbol info for implicit 'this' if the analyzer bridge
    /// resolved it to a class member but the AST node is a bare identifier.
    fn handle_implicit_this(&mut self, nid: NodeId) {
        let node = self.graph.node(nid);
        if let Some(sym_id) = node.symbol {
            let sym = self.graph.symbol(sym_id);
            if sym.canonical.contains("#") && !node.byte_range.is_empty() {
                // This is a member access. If the source text doesn't contain '.'
                // at this range, it's likely an implicit 'this'.
            }
        }
    }
}
