//! Pass 1: AST Builder — CST to CPG Skeleton.
//!
//! Translates Tree-sitter's Concrete Syntax Tree (CST) into our Code
//! Property Graph's AST sub-graph. Establishes the basic node set and
//! parent-child hierarchy.
//!
//! ## Why `member_access` gets special-cased
//!
//! tree-sitter-dart parses `database.rawQuery(...)` as a single
//! `member_access` node containing nested `selector` children, **not** as a
//! `method_invocation`. Likewise `request.body.id` is one `member_access`
//! with two selectors. If we mapped `member_access` straight to a single
//! CPG node, the Semgrep pattern compiler — which expects to see a chain
//! of `MethodCall` nodes whose `symbol` ends with `.<method_name>` —
//! would never match anything.
//!
//! The lowering walks the chain left-to-right and produces a left-leaning
//! tree of nested `MethodCall` nodes:
//!
//! ```text
//!     request.body.id    ─lowers→    MethodCall  (symbol: "request.body.id")
//!                                      ├ slot 0: MethodCall (symbol: "request.body")
//!                                      │           └ slot 0: Identifier "request"
//! ```
//!
//! When a selector contains an `argument_part`, that level is a real call
//! and its arguments are emitted at slots 2, 3, …; pure field-access
//! levels have no slot-2+ children.

use tracing::debug;
use tree_sitter::{Node as TNode, Tree};

use engine_core::cpg::{AstEdge, CodeGraph, EdgeKind, FileId, NodeId, NodeKind};

/// State for the AST construction pass.
pub struct AstBuilder<'g, 's> {
    graph: &'g mut CodeGraph,
    file_id: FileId,
    source: &'s str,
    /// Mapping from Tree-sitter node ID to CPG NodeId. For `member_access`
    /// nodes, this stores the **outermost** lowered MethodCall — i.e. the
    /// node downstream passes (CFG, ICFG, PDG) should treat as the chain
    /// root.
    cst_to_cpg: rustc_hash::FxHashMap<usize, NodeId>,
}

impl<'g, 's> AstBuilder<'g, 's> {
    pub fn new(graph: &'g mut CodeGraph, file_id: FileId, source: &'s str) -> Self {
        Self {
            graph,
            file_id,
            source,
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

        // member_access has its own lowering pipeline (see module docs).
        if node.kind() == "member_access" {
            return self.lower_member_access(node, parent, slot);
        }

        let kind = self.map_kind(node.kind());
        let range = node.start_byte() as u32..node.end_byte() as u32;

        let cpg_id = self.graph.add_node(kind, self.file_id, range);
        self.cst_to_cpg.insert(node.id(), cpg_id);

        // Identifiers and certain leaf-shaped kinds get a symbol so
        // `SymbolEndsWith` / `SymbolContains` predicates can fire. Convert
        // to owned `String` first so the borrow on `self.source` is dropped
        // before we mutably borrow `self.graph`.
        if matches!(kind, NodeKind::Identifier) {
            let text = self.text(&node).to_string();
            let sym_id = self.graph.intern_symbol(&text);
            self.graph.node_mut(cpg_id).symbol = Some(sym_id);
        }

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

    /// Lower a `member_access` chain into a left-leaning tree of MethodCall
    /// nodes. See module docs.
    fn lower_member_access(
        &mut self,
        node: TNode,
        parent: Option<NodeId>,
        slot: u16,
    ) -> Option<NodeId> {
        // Collect the named children. The first is the receiver base
        // (typically `identifier` but could be another expression). Each
        // subsequent child is a `selector`.
        let mut cursor = node.walk();
        let children: Vec<TNode> = node
            .children(&mut cursor)
            .filter(|c| c.is_named())
            .collect();
        if children.is_empty() {
            return None;
        }

        // Recurse into the base — it might be another `member_access` or
        // an `identifier`/`literal`.
        let base = children[0];
        let mut current_id = self.visit_node(base, None, 0)?;
        let mut current_symbol = self.text(&base).to_string();

        // For each selector, build a new MethodCall node wrapping the
        // current one as slot-0 child. If the selector has an
        // `argument_part`, the args become slots 2, 3, …
        for selector in children.iter().skip(1) {
            let (selector_text, args_node) = self.classify_selector(*selector);

            // Update the running symbol with the selector text.
            // selector_text already includes the leading `.` for property
            // selectors and is empty for pure-call selectors.
            current_symbol.push_str(&selector_text);

            // Allocate the new chain level.
            let level_range = node.start_byte() as u32..selector.end_byte() as u32;
            let level_id = self
                .graph
                .add_node(NodeKind::MethodCall, self.file_id, level_range);

            // Attach symbol so `SymbolEndsWith` can match.
            let sym_id = self.graph.intern_symbol(&current_symbol);
            self.graph.node_mut(level_id).symbol = Some(sym_id);

            // Slot 0: the receiver (current_id). Wire AST edge.
            self.graph.add_edge(
                level_id,
                current_id,
                EdgeKind::Ast(AstEdge::Child { slot: 0 }),
            );

            // Slot 2+: arguments, if this selector is a call.
            if let Some(args) = args_node {
                let mut arg_cursor = args.walk();
                let mut arg_slot: u16 = 2;
                for arg_child in args.children(&mut arg_cursor) {
                    if !arg_child.is_named() || arg_child.kind() != "argument" {
                        continue;
                    }
                    // Each `argument` node in tree-sitter-dart wraps the
                    // actual expression. Recurse into the wrapped child.
                    let mut inner_cursor = arg_child.walk();
                    let inner: Option<TNode> =
                        arg_child.children(&mut inner_cursor).find(|c| c.is_named());
                    if let Some(inner_expr) = inner {
                        if let Some(arg_id) = self.visit_node(inner_expr, Some(level_id), arg_slot)
                        {
                            // `visit_node` already attached the AST edge
                            // when parent is Some — nothing else to do.
                            let _ = arg_id;
                        }
                        arg_slot += 1;
                    }
                }
            }

            current_id = level_id;
        }

        // Link the topmost level to its parent in the AST.
        if let Some(pid) = parent {
            self.graph
                .add_edge(pid, current_id, EdgeKind::Ast(AstEdge::Child { slot }));
        }

        // Map the original CST node to the topmost lowered ID.
        self.cst_to_cpg.insert(node.id(), current_id);
        Some(current_id)
    }

    /// Inspect a tree-sitter-dart `selector` node. Returns the textual
    /// suffix to append to the running symbol (empty for pure-call
    /// selectors that wrap only an `argument_part`) and the wrapped
    /// `arguments` node when the selector is a call.
    fn classify_selector<'a>(&self, selector: TNode<'a>) -> (String, Option<TNode<'a>>) {
        let mut cursor = selector.walk();
        let mut text_suffix = String::new();
        let mut args_node: Option<TNode> = None;

        for child in selector.children(&mut cursor) {
            match child.kind() {
                "unconditional_assignable_selector" | "conditional_assignable_selector" => {
                    text_suffix.push_str(self.text(&child));
                }
                "argument_part" => {
                    let mut ac = child.walk();
                    args_node = child
                        .children(&mut ac)
                        .find(|c| c.is_named() && c.kind() == "arguments");
                }
                _ if child.is_named() => {
                    // Fallback: fold the entire selector text in. This
                    // covers grammar variants we haven't enumerated.
                    if text_suffix.is_empty() {
                        text_suffix.push_str(self.text(&selector));
                    }
                }
                _ => {}
            }
        }

        if text_suffix.is_empty() && args_node.is_none() {
            // Defensive: never seen empirically, but keeps the symbol
            // chain coherent if tree-sitter-dart adds new selector shapes.
            text_suffix.push_str(self.text(&selector));
        }

        (text_suffix, args_node)
    }

    /// Borrow the source text covered by a CST node.
    fn text<'a>(&'a self, node: &TNode) -> &'a str {
        &self.source[node.start_byte()..node.end_byte()]
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
            "lambda_expression" => NodeKind::FunctionDecl,
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
            // tree-sitter-dart uses `member_access` for both method calls
            // and field reads. We special-case it in `lower_member_access`
            // and never reach this map_kind for it; the entry below is a
            // belt-and-braces fallback.
            "member_access" => NodeKind::MethodCall,
            "method_invocation" => NodeKind::MethodCall,
            "function_expression_invocation" => NodeKind::Call,
            "instance_creation_expression" => NodeKind::ConstructorCall,

            "identifier" => NodeKind::Identifier,
            "string_literal" | "raw_string_literal" => NodeKind::Literal,
            "integer_literal" | "hex_integer_literal" => NodeKind::Literal,
            "boolean_literal" | "null_literal" => NodeKind::Literal,
            "string_interpolation" => NodeKind::StringInterp,

            "formal_parameter" => NodeKind::Parameter,
            // The variable name node for `final id = ...`. Treat it as a
            // local definition so PDG def-use chains can resolve it.
            "initialized_variable_definition" => NodeKind::Local,

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
