//! Pass 2: CFG Builder — Intra-procedural Control Flow.
//!
//! This module layers control-flow edges onto the AST. It identifies
//! procedures (functions/methods), allocates Entry and Exit nodes,
//! and connects statements following the program's execution pulse.

use tracing::{debug, info};
use tree_sitter::Node as TNode;

use engine_core::cpg::{CfgEdge, CodeGraph, EdgeKind, NodeId, NodeKind};

/// State for the CFG construction pass.
pub struct CfgBuilder<'g> {
    graph: &'g mut CodeGraph,
    cst_to_cpg: rustc_hash::FxHashMap<usize, NodeId>,
    /// The "cursor" of execution.
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

    /// Build CFG edges for the workspace.
    pub fn build(&mut self, root: TNode) {
        self.visit_node(root);
    }

    fn visit_node(&mut self, node: TNode) {
        let ts_kind = node.kind();

        match ts_kind {
            "method_declaration" | "function_declaration" => {
                self.process_procedure(node);
            }
            _ => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.visit_node(child);
                }
            }
        }
    }

    /// Process a function/method: create Entry/Exit and link the body.
    fn process_procedure(&mut self, node: TNode) {
        let Some(&proc_node_id) = self.cst_to_cpg.get(&node.id()) else {
            return;
        };

        let file_id = self.graph.node(proc_node_id).file;
        let range = self.graph.node(proc_node_id).byte_range.clone();

        // 1. Create Entry and Exit nodes.
        let entry_id = self
            .graph
            .add_node(NodeKind::EntryNode, file_id, range.start..range.start);
        let exit_id = self
            .graph
            .add_node(NodeKind::ExitNode, file_id, range.end..range.end);

        // 2. Patch procedure pointers for the header.
        self.graph.node_mut(proc_node_id).procedure = Some(entry_id);
        self.graph.node_mut(entry_id).procedure = Some(entry_id);
        self.graph.node_mut(exit_id).procedure = Some(entry_id);

        // 3. Start execution at the Entry node.
        self.frontier = vec![entry_id];

        // 4. Find the body and process it.
        if let Some(body) = node.child_by_field_name("body") {
            self.process_statement_list(body, entry_id);
        }

        // 5. Connect the remaining frontier to the Exit node.
        for &f in &self.frontier {
            self.graph
                .add_edge(f, exit_id, EdgeKind::Cfg(CfgEdge::Fall));
        }
    }

    fn process_statement_list(&mut self, node: TNode, entry_id: NodeId) {
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

        let ts_kind = node.kind();
        match ts_kind {
            "block" => {
                self.process_statement_list(node, entry_id);
            }
            "if_statement" => {
                self.process_if(node, cpg_id, entry_id);
            }
            "return_statement" => {
                // Return terminates the current branch (linked to exit later).
                for &f in &self.frontier {
                    self.graph.add_edge(f, cpg_id, EdgeKind::Cfg(CfgEdge::Fall));
                }
                self.frontier.clear();
            }
            _ => {
                // Linear statement: link frontier to this, update frontier.
                for &f in &self.frontier {
                    self.graph.add_edge(f, cpg_id, EdgeKind::Cfg(CfgEdge::Fall));
                }
                self.frontier = vec![cpg_id];

                // Note: We do NOT recurse here. The AST pass already built the
                // sub-tree. Data-flow (PDG) will handle the internal dependencies.
                // Control-flow only cares about the statement as a whole unit.
            }
        }
    }

    fn process_if(&mut self, node: TNode, if_id: NodeId, entry_id: NodeId) {
        // Link frontier to the 'if' header.
        for &f in &self.frontier {
            self.graph.add_edge(f, if_id, EdgeKind::Cfg(CfgEdge::Fall));
        }

        // Process 'consequence' (then block).
        self.frontier = vec![if_id]; // Start 'then' branch from 'if'
        if let Some(consequence) = node.child_by_field_name("consequence") {
            self.process_statement(consequence, entry_id);
        }
        let then_frontier = self.frontier.clone();

        // Process 'alternative' (else block).
        self.frontier = vec![if_id]; // Start 'else' branch from 'if'
        if let Some(alternative) = node.child_by_field_name("alternative") {
            // Note: tree-sitter-dart 'alternative' usually includes the 'else' keyword.
            self.process_statement(alternative, entry_id);
        }
        let else_frontier = self.frontier.clone();

        // Merge frontiers.
        self.frontier = then_frontier;
        self.frontier.extend(else_frontier);
    }
}
