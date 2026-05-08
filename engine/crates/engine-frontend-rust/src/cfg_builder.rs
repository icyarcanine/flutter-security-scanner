//! Pass 2 (Rust): CFG Builder — Intra-procedural Control Flow.
//!
//! Handles Rust's sophisticated control flow, including `match`, `if let`,
//! `loop`, and implicit returns (last expression in a block).

use tracing::debug;
use tree_sitter::Node as TNode;

use engine_core::cpg::{CfgEdge, CodeGraph, EdgeKind, NodeId, NodeKind};

pub struct CfgBuilder<'g> {
    graph: &'g mut CodeGraph,
    cst_to_cpg: rustc_hash::FxHashMap<usize, NodeId>,
    frontier: Vec<NodeId>,
}

impl<'g> CfgBuilder<'g> {
    pub fn new(graph: &'g mut CodeGraph, cst_to_cpg: rustc_hash::FxHashMap<usize, NodeId>) -> Self {
        Self {
            graph,
            cst_to_cpg,
            frontier: Vec::new(),
        }
    }

    pub fn build(&mut self, root: TNode) {
        self.visit_node(root);
    }

    fn visit_node(&mut self, node: TNode) {
        match node.kind() {
            "function_item" => self.process_procedure(node),
            _ => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.visit_node(child);
                }
            }
        }
    }

    fn process_procedure(&mut self, node: TNode) {
        let Some(&proc_node_id) = self.cst_to_cpg.get(&node.id()) else {
            return;
        };
        let file_id = self.graph.node(proc_node_id).file;
        let range = self.graph.node(proc_node_id).byte_range.clone();

        let entry_id = self
            .graph
            .add_node(NodeKind::EntryNode, file_id, range.start..range.start);
        let exit_id = self
            .graph
            .add_node(NodeKind::ExitNode, file_id, range.end..range.end);

        self.graph.node_mut(proc_node_id).procedure = Some(entry_id);
        self.graph.node_mut(entry_id).procedure = Some(entry_id);
        self.graph.node_mut(exit_id).procedure = Some(entry_id);

        self.frontier = vec![entry_id];

        if let Some(body) = node.child_by_field_name("body") {
            self.process_block(body, entry_id);
        }

        for &f in &self.frontier {
            self.graph
                .add_edge(f, exit_id, EdgeKind::Cfg(CfgEdge::Fall));
        }
    }

    fn process_block(&mut self, node: TNode, entry_id: NodeId) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.process_statement(child, entry_id);
        }
    }

    fn process_statement(&mut self, node: TNode, entry_id: NodeId) {
        if !node.is_named() {
            return;
        }
        let Some(&cpg_id) = self.cst_to_cpg.get(&node.id()) else {
            return;
        };
        self.graph.node_mut(cpg_id).procedure = Some(entry_id);

        match node.kind() {
            "block" | "unsafe_block" => self.process_block(node, entry_id),
            "if_expression" => self.process_if(node, cpg_id, entry_id),
            "match_expression" => self.process_match(node, cpg_id, entry_id),
            "return_expression" => {
                for &f in &self.frontier {
                    self.graph.add_edge(f, cpg_id, EdgeKind::Cfg(CfgEdge::Fall));
                }
                self.frontier.clear();
            }
            _ => {
                for &f in &self.frontier {
                    self.graph.add_edge(f, cpg_id, EdgeKind::Cfg(CfgEdge::Fall));
                }
                self.frontier = vec![cpg_id];
            }
        }
    }

    fn process_if(&mut self, node: TNode, if_id: NodeId, entry_id: NodeId) {
        for &f in &self.frontier {
            self.graph.add_edge(f, if_id, EdgeKind::Cfg(CfgEdge::Fall));
        }

        self.frontier = vec![if_id];
        if let Some(consequence) = node.child_by_field_name("consequence") {
            self.process_statement(consequence, entry_id);
        }
        let then_frontier = self.frontier.clone();

        self.frontier = vec![if_id];
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.process_statement(alternative, entry_id);
        }
        let else_frontier = self.frontier.clone();

        self.frontier = then_frontier;
        self.frontier.extend(else_frontier);
    }

    fn process_match(&mut self, node: TNode, match_id: NodeId, entry_id: NodeId) {
        for &f in &self.frontier {
            self.graph
                .add_edge(f, match_id, EdgeKind::Cfg(CfgEdge::Fall));
        }

        let mut arms_frontier = Vec::new();
        let mut cursor = node.walk();
        for arm in node.children_by_field_name("arms", &mut cursor) {
            self.frontier = vec![match_id];
            self.process_statement(arm, entry_id);
            arms_frontier.extend(self.frontier.clone());
        }

        self.frontier = arms_frontier;
    }
}
