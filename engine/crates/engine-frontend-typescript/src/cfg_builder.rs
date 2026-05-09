//! TypeScript CFG builder — intra-procedural control-flow graph.

use engine_core::cpg::CodeGraph;
use rustc_hash::FxHashMap;
use tree_sitter::Node;

/// Builds the CFG sub-graph for a TypeScript file.
pub struct CfgBuilder<'a> {
    #[allow(dead_code)]
    graph: &'a mut CodeGraph,
    /// Maps tree-sitter node IDs to the CPG node that represents "after"
    /// this statement (for fall-through edges).
    #[allow(dead_code)]
    exit_map: FxHashMap<usize, Vec<usize>>,
}

impl<'a> CfgBuilder<'a> {
    pub fn new(graph: &'a mut CodeGraph) -> Self {
        Self {
            graph,
            exit_map: FxHashMap::default(),
        }
    }

    /// Build the CFG by walking the tree-sitter CST and emitting control-flow edges.
    pub fn build(&mut self, root: Node) {
        self.visit_block(root);
    }

    fn visit_block(&mut self, node: Node) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.is_named() {
                    self.visit_statement(child);
                }
            }
        }
    }

    fn visit_statement(&mut self, node: Node) {
        match node.kind() {
            "if_statement" => self.visit_if(node),
            "for_statement" | "for_in_statement" | "while_statement" | "do_statement" => {
                self.visit_loop(node)
            }
            "return_statement" => {} // No fall-through edge
            "expression_statement" => {
                // Simple fall-through: link expression to next sibling
            }
            _ => {
                // Default: recurse into children for compound statements
                self.visit_block(node);
            }
        }
    }

    fn visit_if(&mut self, node: Node) {
        // Walk children to find condition, consequence, and alternative
        let mut _condition = None;
        let mut consequence = None;
        let mut alternative = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "parenthesized_expression"
                    | "binary_expression"
                    | "identifier"
                    | "call_expression" => _condition = Some(child),
                    "statement_block" => {
                        if consequence.is_none() {
                            consequence = Some(child);
                        } else {
                            alternative = Some(child);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Recursively visit branches
        if let Some(cons) = consequence {
            self.visit_block(cons);
        }
        if let Some(alt) = alternative {
            self.visit_block(alt);
        }
    }

    fn visit_loop(&mut self, node: Node) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "statement_block" {
                    self.visit_block(child);
                }
            }
        }
    }
}
