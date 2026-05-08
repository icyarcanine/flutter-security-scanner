//! Pass 1: AST Builder — CST to CPG Skeleton.
//!
//! This module performs the mechanical translation from Tree-sitter's
//! Concrete Syntax Tree (CST) to our Code Property Graph's AST sub-graph.
//! It establishes the basic node set and the parent-child hierarchy.

use std::ops::Range;
use tracing::{debug, warn};
use tree_sitter::{Node as TNode, Tree};

use engine_core::cpg::{AstEdge, CodeGraph, EdgeKind, FileId, NodeId, NodeKind};

/// State for the AST construction pass.
pub struct AstBuilder<'g> {
    graph: &'g mut CodeGraph,
    file_id: FileId,
    /// Mapping from Tree-sitter node ID to CPG NodeId.
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

    /// Build the AST sub-graph for a parsed Tree.
    pub fn build(&mut self, tree: &Tree) {
        let root = tree.root_node();
        self.visit_node(root, None, 0);
    }

    /// Recursively visit CST nodes.
    fn visit_node(&mut self, node: TNode, parent: Option<NodeId>, slot: u16) -> Option<NodeId> {
        if !node.is_named() {
            return None;
        }

        let kind = self.map_kind(node.kind());
        let range = node.start_byte() as u32..node.end_byte() as u32;

        // Allocate the CPG node.
        let cpg_id = self.graph.add_node(kind, self.file_id, range);
        self.cst_to_cpg.insert(node.id(), cpg_id);

        // Link to parent.
        if let Some(pid) = parent {
            self.graph
                .add_edge(pid, cpg_id, EdgeKind::Ast(AstEdge::Child { slot }));
        }

        // Recursively visit children.
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

    /// Map Tree-sitter node types to our internal NodeKind.
    ///
    /// The mapping is deliberately conservative: CST kinds that don't have a
    /// canonical IR equivalent fall through to `Unknown` rather than being
    /// shoehorned into a similar-but-different variant. The IFDS solver
    /// treats `Unknown` as opaque — better than a wrong classification.
    fn map_kind(&self, ts_kind: &str) -> NodeKind {
        match ts_kind {
            "program" => NodeKind::Module,
            "class_definition" => NodeKind::ClassDecl,
            "mixin_definition" => NodeKind::MixinDecl,
            "extension_definition" => NodeKind::ExtensionDecl,

            "method_declaration" => NodeKind::MethodDecl,
            "function_declaration" => NodeKind::FunctionDecl,
            "constructor_declaration" | "factory_constructor_signature" => {
                NodeKind::ConstructorDecl
            }
            "getter_signature" => NodeKind::GetterDecl,
            "setter_signature" => NodeKind::SetterDecl,

            "expression_statement" => NodeKind::ExprStmt,
            "if_statement" => NodeKind::If,
            "for_statement" | "while_statement" | "do_statement" => NodeKind::Loop,
            "try_statement" => NodeKind::Try,
            "return_statement" => NodeKind::Return,
            "switch_statement" => NodeKind::Switch,

            "assignment_expression" | "pattern_assignment" => NodeKind::Assign,
            "method_invocation" => NodeKind::MethodCall,
            "function_expression_invocation" => NodeKind::Call,
            "instance_creation_expression" => NodeKind::ConstructorCall,

            "identifier" => NodeKind::Identifier,
            "string_literal" | "raw_string_literal" => NodeKind::Literal,
            "integer_literal" | "hex_integer_literal" => NodeKind::Literal,
            "boolean_literal" | "null_literal" => NodeKind::Literal,
            "string_interpolation" => NodeKind::StringInterp,

            "formal_parameter" => NodeKind::Parameter,

            _ => {
                debug!(?ts_kind, "unmapped tree-sitter kind, defaulting to Unknown");
                NodeKind::Unknown
            }
        }
    }

    /// Get the mapping from CST to CPG for subsequent passes.
    pub fn mapping(self) -> rustc_hash::FxHashMap<usize, NodeId> {
        self.cst_to_cpg
    }
}
