//! TypeScript AST builder — lowers tree-sitter CST into the CPG AST sub-graph.

use engine_core::cpg::{AstEdge, CodeGraph, EdgeKind, FileId, NodeId, NodeKind};
use rustc_hash::FxHashMap;
use tree_sitter::{Node, Tree};

/// Builds the AST sub-graph for a TypeScript file.
pub struct AstBuilder<'a> {
    graph: &'a mut CodeGraph,
    file_id: FileId,
    /// Maps tree-sitter node IDs to CPG NodeIds for sibling-chain construction.
    node_map: FxHashMap<usize, NodeId>,
    /// Stack tracking the parent chain during traversal.
    parent_stack: Vec<(NodeId, u16)>,
}

impl<'a> AstBuilder<'a> {
    pub fn new(graph: &'a mut CodeGraph, file_id: FileId, _source: &'a str) -> Self {
        Self {
            graph,
            file_id,
            node_map: FxHashMap::default(),
            parent_stack: Vec::new(),
        }
    }

    /// Walk the tree-sitter CST and emit CPG AST nodes + Ast::Child edges.
    pub fn build(&mut self, tree: &Tree) {
        let root = tree.root_node();
        self.visit_node(root, 0);
        self.build_sibling_chains();
    }

    /// Recursively lower a tree-sitter node to a CPG node.
    fn visit_node(&mut self, node: Node, slot: u16) -> NodeId {
        let kind = self.map_kind(&node);
        let cpg_id = self.graph.add_node(
            kind,
            self.file_id,
            node.start_byte() as u32..node.end_byte() as u32,
        );
        self.node_map.insert(node.id(), cpg_id);

        // Emit parent→child edge
        if let Some(&(parent_id, _)) = self.parent_stack.last() {
            self.graph
                .add_edge(parent_id, cpg_id, EdgeKind::Ast(AstEdge::Child { slot }));
        }

        // Recurse into children
        self.parent_stack.push((cpg_id, slot));
        let mut child_slot: u16 = 0;
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.is_named() {
                    self.visit_node(child, child_slot);
                    child_slot += 1;
                }
            }
        }
        self.parent_stack.pop();

        cpg_id
    }

    /// Map tree-sitter node types to CPG NodeKinds.
    fn map_kind(&self, node: &Node) -> NodeKind {
        match node.kind() {
            // Program / module
            "program" | "module" => NodeKind::Module,

            // Declarations
            "function_declaration" => NodeKind::FunctionDecl,
            "method_definition" => NodeKind::MethodDecl,
            "class_declaration" => NodeKind::ClassDecl,
            "interface_declaration" | "type_alias_declaration" => NodeKind::ExtensionDecl,
            "arrow_function" | "function_expression" => NodeKind::Lambda,
            "generator_function_declaration" => NodeKind::FunctionDecl,

            // Variables
            "variable_declarator" => NodeKind::Local,
            "required_parameter" | "optional_parameter" => NodeKind::Parameter,

            // Literals
            "string" | "string_fragment" | "template_string" | "number" | "true" | "false"
            | "null" | "undefined" => NodeKind::Literal,

            // Identifiers
            "identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern" => {
                // Check if this identifier is part of a call expression (method call)
                if let Some(parent) = node.parent() {
                    if parent.kind() == "call_expression" {
                        return NodeKind::Call;
                    }
                }
                NodeKind::Identifier
            }

            // Expressions
            "call_expression" => NodeKind::Call,
            "member_expression" | "subscript_expression" => NodeKind::FieldRead,
            "assignment_expression" => NodeKind::Assign,
            "binary_expression" => NodeKind::BinaryOp,
            "unary_expression" => NodeKind::UnaryOp,
            "await_expression" => NodeKind::AwaitExpr,
            "ternary_expression" => NodeKind::Conditional,
            "new_expression" => NodeKind::ConstructorCall,
            "array" | "array_expression" => NodeKind::Literal,
            "object" | "object_expression" => NodeKind::Literal,
            "template_substitution" => NodeKind::StringInterp,

            // Statements
            "expression_statement" => NodeKind::ExprStmt,
            "if_statement" => NodeKind::If,
            "switch_statement" => NodeKind::Switch,
            "switch_case" | "case_expression" => NodeKind::SwitchCase,
            "for_statement" | "for_in_statement" | "while_statement" | "do_statement" => {
                NodeKind::Loop
            }
            "break_statement" => NodeKind::Break,
            "continue_statement" => NodeKind::Continue,
            "return_statement" => NodeKind::Return,
            "try_statement" => NodeKind::Try,
            "catch_clause" => NodeKind::Catch,
            "throw_statement" => NodeKind::ThrowExpr,

            _ => NodeKind::Unknown,
        }
    }

    /// Emit NextSibling edges between consecutive children of each parent.
    fn build_sibling_chains(&mut self) {
        let nodes: Vec<(NodeId, NodeId)> = {
            let graph = &self.graph;
            // Collect parents with >1 child from the AST edge arena
            let mut parents: FxHashMap<NodeId, Vec<NodeId>> = FxHashMap::default();
            for edge in graph.iter_edges() {
                if let EdgeKind::Ast(AstEdge::Child { .. }) = edge.kind {
                    parents.entry(edge.src).or_default().push(edge.dst);
                }
            }
            let mut sibling_edges = Vec::new();
            for children in parents.values() {
                for pair in children.windows(2) {
                    sibling_edges.push((pair[0], pair[1]));
                }
            }
            sibling_edges
        };

        for (prev, next) in nodes {
            self.graph
                .add_edge(prev, next, EdgeKind::Ast(AstEdge::NextSibling));
        }
    }
}
