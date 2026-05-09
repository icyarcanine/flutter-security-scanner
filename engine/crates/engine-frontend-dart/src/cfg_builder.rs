//! Pass 2: CFG Builder — Intra-procedural Control Flow.
//!
//! This module layers control-flow edges onto the AST. It identifies
//! procedures (functions/methods), allocates Entry and Exit nodes,
//! and connects statements following the program's execution pulse.

use tree_sitter::Node as TNode;

use engine_core::cpg::{AstEdge, CfgEdge, CodeGraph, EdgeKind, EdgeKindTag, NodeId, NodeKind};

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
            // tree-sitter-dart wraps top-level functions as `lambda_expression`
            // (a `function_signature` + `function_body` pair). Without this
            // arm the CFG builder never walks function bodies and IFDS gets
            // an empty CFG to traverse.
            "method_declaration" | "function_declaration" | "lambda_expression" => {
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

        // 4. Wire formal parameters into the CFG so IFDS can propagate
        //    taint from parameter declarations to the body. Parameters are
        //    "available" at function entry, so Entry → Param₁ → Param₂ → …
        //    is the natural execution order.
        self.wire_parameters(node, entry_id);

        // 5. Find the body and process it.
        if let Some(body) = node.child_by_field_name("body") {
            self.process_statement_list(body, entry_id);
        }

        // 6. Connect the remaining frontier to the Exit node.
        for &f in &self.frontier {
            self.graph
                .add_edge(f, exit_id, EdgeKind::Cfg(CfgEdge::Fall));
        }
    }

    /// Walk the CST looking for `formal_parameter_list` children and wire
    /// each parameter's CPG node into the CFG fall-through chain.
    fn wire_parameters(&mut self, node: TNode, entry_id: NodeId) {
        if let Some(param_list) = Self::find_child_recursive(node, "formal_parameter_list") {
            let mut param_cursor = param_list.walk();
            for param in param_list.children(&mut param_cursor) {
                if !param.is_named() {
                    continue;
                }
                // The CPG node for the parameter was created by the AST
                // builder.  Tree-sitter node IDs are stable within a
                // parse, so the mapping should contain it.
                if let Some(&param_id) = self.cst_to_cpg.get(&param.id()) {
                    self.graph.node_mut(param_id).procedure = Some(entry_id);
                    for &f in &self.frontier {
                        self.graph
                            .add_edge(f, param_id, EdgeKind::Cfg(CfgEdge::Fall));
                    }
                    self.frontier = vec![param_id];
                }
            }
        }
    }

    /// Recursively search for a child with the given kind.
    fn find_child_recursive<'a>(node: TNode<'a>, kind: &str) -> Option<TNode<'a>> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == kind {
                return Some(child);
            }
            if let Some(found) = Self::find_child_recursive(child, kind) {
                return Some(found);
            }
        }
        None
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

                // Extend the CFG into the statement's expression tree by
                // walking AST descendants in pre-order and chaining a
                // Fall edge through each. This lets the IFDS solver visit
                // *every* expression node — without it, source/sink
                // detection on nested MethodCall chains never fires
                // because IFDS only traverses CFG/RDG edges.
                self.extend_into_expression(cpg_id, entry_id);
            }
        }
    }

    /// Walk the AST sub-tree rooted at `stmt_id` in **post-order**
    /// (descendants before parent) and add `Cfg::Fall` edges along that
    /// order. Post-order matches actual evaluation order — leaf values
    /// are computed first and flow up to enclosing expressions — which
    /// is what the IFDS solver needs to propagate taint from a source
    /// (typically a leaf) to a sink (typically an enclosing call).
    ///
    /// After the walk `self.frontier` points at the parent statement
    /// (`stmt_id`), since execution returns to the statement boundary
    /// before falling through to the next statement.
    ///
    /// Cycle-safe via a `visited` set so pathological lowerings with
    /// shared sub-trees do not loop.
    fn extend_into_expression(&mut self, stmt_id: NodeId, entry_id: NodeId) {
        let mut order: Vec<NodeId> = Vec::new();
        let mut visited: rustc_hash::FxHashSet<NodeId> = rustc_hash::FxHashSet::default();
        Self::collect_postorder(self.graph, stmt_id, &mut visited, &mut order);

        // `order` is [descendant_leaf, …, stmt_id]. Wire Fall edges along
        // that order, but skip the first hop because the statement→first
        // node link is already in place (frontier was just set to
        // [stmt_id]).
        if order.len() <= 1 {
            return;
        }

        // Replace frontier-edge to point at the leftmost leaf instead of
        // stmt_id. We do this by adding a Fall stmt_id → first_leaf and
        // then chaining through the remaining order.
        let mut prev: Option<NodeId> = Some(stmt_id);
        for &node in &order {
            if node == stmt_id {
                continue;
            }
            self.graph.node_mut(node).procedure.get_or_insert(entry_id);
            if let Some(p) = prev {
                self.graph.add_edge(p, node, EdgeKind::Cfg(CfgEdge::Fall));
            }
            prev = Some(node);
        }

        if let Some(last) = prev {
            if last != stmt_id {
                self.frontier = vec![last];
            }
        }
    }

    /// Iterative post-order traversal over AST children. Children are
    /// visited in slot order before the parent.
    fn collect_postorder(
        graph: &CodeGraph,
        root: NodeId,
        visited: &mut rustc_hash::FxHashSet<NodeId>,
        out: &mut Vec<NodeId>,
    ) {
        // Standard iterative post-order: push pairs (node, expanded:bool).
        // First pop expands the children; second pop emits the node.
        let mut stack: Vec<(NodeId, bool)> = vec![(root, false)];
        while let Some((node, expanded)) = stack.pop() {
            if expanded {
                out.push(node);
                continue;
            }
            if !visited.insert(node) {
                continue;
            }
            stack.push((node, true));

            // Collect AST children in slot order, push in reverse so they
            // pop in slot order.
            let mut children: Vec<(u16, NodeId)> = Vec::new();
            for edge in graph.out_edges(node, EdgeKindTag::Ast) {
                if let EdgeKind::Ast(AstEdge::Child { slot }) = edge.kind {
                    children.push((slot, edge.dst));
                }
            }
            children.sort_by_key(|&(s, _)| s);
            for (_slot, child) in children.into_iter().rev() {
                stack.push((child, false));
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
