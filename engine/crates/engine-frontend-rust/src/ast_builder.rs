//! Pass 1 (Rust): AST Builder — CST to CPG Skeleton.
//!
//! This module translates Tree-sitter's Rust CST into our universal CPG.
//! It handles Rust-specific constructs like `struct`, `impl`, `match`, and
//! critical security markers like `unsafe` blocks.

use tree_sitter::{Node as TNode, Tree};

use engine_core::cpg::{AstEdge, CodeGraph, EdgeKind, FileId, NodeId, NodeKind};

pub struct AstBuilder<'g> {
    graph: &'g mut CodeGraph,
    file_id: FileId,
    cst_to_cpg: rustc_hash::FxHashMap<usize, NodeId>,
}

impl<'g> AstBuilder<'g> {
    pub fn new(graph: &'g mut CodeGraph, file_id: FileId) -> Self {
        Self {
            graph,
            file_id,
            cst_to_cpg: rustc_hash::FxHashMap::default(),
        }
    }

    pub fn build(&mut self, tree: &Tree) {
        let root = tree.root_node();
        self.visit_node(root, None, 0);
    }

    fn visit_node(&mut self, node: TNode, parent: Option<NodeId>, slot: u16) -> Option<NodeId> {
        if !node.is_named() {
            return None;
        }

        let kind = self.map_kind(node.kind());
        let range = node.start_byte() as u32..node.end_byte() as u32;

        let cpg_id = self.graph.add_node(kind, self.file_id, range);
        self.cst_to_cpg.insert(node.id(), cpg_id);

        if let Some(pid) = parent {
            self.graph
                .add_edge(pid, cpg_id, EdgeKind::Ast(AstEdge::Child { slot }));
        }

        let mut cursor = node.walk();
        let mut child_slot = 0;
        for child in node.children(&mut cursor) {
            if child.is_named() {
                self.visit_node(child, Some(cpg_id), child_slot);
                child_slot += 1;
            }
        }

        Some(cpg_id)
    }

    fn map_kind(&self, ts_kind: &str) -> NodeKind {
        match ts_kind {
            "source_file" => NodeKind::Module,
            "struct_item" => NodeKind::ClassDecl,
            "enum_item" => NodeKind::ClassDecl,
            "impl_item" => NodeKind::ClassDecl,

            "function_item" => NodeKind::FunctionDecl,
            "function_signature_item" => NodeKind::FunctionDecl,

            "block" | "unsafe_block" => NodeKind::ExprStmt,
            "let_declaration" => NodeKind::Assign,
            "if_expression" => NodeKind::If,
            "for_expression" | "while_expression" | "loop_expression" => NodeKind::Loop,
            "match_expression" => NodeKind::Switch,
            "return_expression" => NodeKind::Return,

            "call_expression" => NodeKind::Call,
            "method_call_expression" => NodeKind::MethodCall,
            "struct_expression" => NodeKind::ConstructorCall,

            "identifier" | "field_identifier" => NodeKind::Identifier,
            "string_literal" | "char_literal" => NodeKind::Literal,
            "integer_literal" | "float_literal" => NodeKind::Literal,
            "boolean_literal" => NodeKind::Literal,

            "parameter" => NodeKind::Parameter,

            _ => NodeKind::Unknown,
        }
    }

    pub fn mapping(self) -> rustc_hash::FxHashMap<usize, NodeId> {
        self.cst_to_cpg
    }
}
