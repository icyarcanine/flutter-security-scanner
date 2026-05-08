//! Reactive Dependency Graph (RDG) edge populator.
//!
//! This module runs **after** the semantic bridge has resolved types and
//! **before** the IFDS solver runs. It walks the CPG looking for reactive
//! framework patterns (stream emissions, state writes, widget subscriptions)
//! and inserts the [`RdgEdge`] edges that make implicit reactive data-flow
//! visible to the solver.
//!
//! Without these edges, taint "vanishes" at every `sink.add()` or
//! `setState()` boundary — a catastrophic false negative that no competing
//! SAST tool currently closes.
//!
//! # Supported frameworks
//!
//! | Framework       | Emission pattern                | Subscription pattern            |
//! |-----------------|---------------------------------|---------------------------------|
//! | dart:async      | `StreamController.add(x)`       | `stream.listen(cb)`, `StreamBuilder` |
//! | Riverpod 1.x    | `state = newValue`              | `ref.watch(provider)`, `ConsumerWidget.build` |
//! | Riverpod 2.x    | `state = newValue` in Notifier  | same                            |
//! | flutter_bloc    | `emit(newState)`                | `BlocBuilder`, `BlocListener`   |
//! | Provider/CN     | `notifyListeners()`             | `Provider.of<T>(context)`, `context.watch<T>()` |
//! | ValueNotifier   | `value = newValue`              | `ValueListenableBuilder`        |
//!
//! # Algorithm
//!
//! The builder runs in four phases:
//!
//! 1. **Discover emitters:** walk all method-call and field-write nodes,
//!    check their resolved type against the type arena, collect emitter
//!    anchors keyed by the reactive channel's `SymbolId`.
//! 2. **Discover subscribers:** mirror of phase 1 for subscription patterns.
//! 3. **Discover build methods:** find `build()` methods of reactive widget
//!    classes and tag them as `BuildMethod` nodes.
//! 4. **Wire edges:** for each emitter, find all subscribers and build
//!    methods that reference the same channel/provider, and insert RDG
//!    edges.

use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use tracing::{debug, info};

use crate::cpg::{CodeGraph, EdgeKind, EdgeKindTag, NodeId, NodeKind, RdgEdge, SymbolId, TypeRef};
use crate::frontend::types::TypeArena;

// ============================================================================
// Public API
// ============================================================================

/// Build all RDG edges for the given CPG + type arena. Returns the number
/// of edges inserted.
pub fn build_rdg(graph: &mut CodeGraph, types: &TypeArena) -> usize {
    let mut ctx = BuilderContext::new(graph, types);
    ctx.phase1_discover_emitters();
    ctx.phase2_discover_subscribers();
    ctx.phase3_discover_build_methods();
    let count = ctx.phase4_wire_edges();
    info!(
        emitters = ctx.emitters.values().map(Vec::len).sum::<usize>(),
        subscribers = ctx.subscribers.values().map(Vec::len).sum::<usize>(),
        build_methods = ctx.build_methods.values().map(Vec::len).sum::<usize>(),
        edges = count,
        "RDG construction complete"
    );
    count
}

// ============================================================================
// Builder context
// ============================================================================

/// Tracks discovered reactive anchors during the four-phase build.
struct BuilderContext<'g, 't> {
    graph: &'g mut CodeGraph,
    types: &'t TypeArena,
    /// Channel/provider symbol → emitter node ids.
    emitters: FxHashMap<SymbolId, Vec<NodeId>>,
    /// Channel/provider symbol → subscriber node ids.
    subscribers: FxHashMap<SymbolId, Vec<NodeId>>,
    /// Provider/notifier symbol → build-method node ids (widgets that read it).
    build_methods: FxHashMap<SymbolId, Vec<NodeId>>,
}

impl<'g, 't> BuilderContext<'g, 't> {
    fn new(graph: &'g mut CodeGraph, types: &'t TypeArena) -> Self {
        Self {
            graph,
            types,
            emitters: FxHashMap::default(),
            subscribers: FxHashMap::default(),
            build_methods: FxHashMap::default(),
        }
    }

    // -- Phase 1: discover emitters ---------------------------------------

    fn phase1_discover_emitters(&mut self) {
        // Snapshot node ids to avoid borrowing graph during mutation.
        let nodes: Vec<(NodeId, NodeKind, Option<SymbolId>)> = self
            .graph
            .iter_nodes()
            .map(|n| (n.id, n.kind, n.symbol))
            .collect();

        for (nid, kind, sym) in &nodes {
            match kind {
                // MethodCall: StreamController.add(), Bloc.emit(),
                //             notifyListeners(), sink.add()
                NodeKind::MethodCall => {
                    self.check_method_emitter(*nid, *sym);
                }
                // FieldWrite: StateNotifier.state = ...,
                //             ValueNotifier.value = ...
                NodeKind::FieldWrite | NodeKind::Assign => {
                    self.check_field_emitter(*nid, *sym);
                }
                _ => {}
            }
        }
    }

    /// Check if a method call is a reactive emission.
    fn check_method_emitter(&mut self, node: NodeId, _sym: Option<SymbolId>) {
        let method_name = self.method_name_of(node);

        // Stream pattern: receiver.add(x) / receiver.addError(x)
        if matches!(
            method_name.as_deref(),
            Some("add" | "addError" | "addStream")
        ) {
            if let Some(receiver_type) = self.receiver_type(node) {
                if self.types.is_stream_controller(receiver_type)
                    || self.types.is_stream_sink(receiver_type)
                {
                    if let Some(channel) = self.receiver_symbol(node) {
                        debug!(?node, channel_id = channel.0, "discovered stream emitter");
                        self.emitters.entry(channel).or_default().push(node);
                        return;
                    }
                }
            }
        }

        // BLoC pattern: emit(newState)
        if method_name.as_deref() == Some("emit") {
            if let Some(enclosing_type) = self.enclosing_class_type(node) {
                if self.types.is_bloc_base(enclosing_type) {
                    if let Some(bloc_sym) = self.enclosing_class_symbol(node) {
                        debug!(?node, bloc_sym_id = bloc_sym.0, "discovered BLoC emitter");
                        self.emitters.entry(bloc_sym).or_default().push(node);
                        return;
                    }
                }
            }
        }

        // ChangeNotifier pattern: notifyListeners()
        if method_name.as_deref() == Some("notifyListeners") {
            if let Some(enclosing_type) = self.enclosing_class_type(node) {
                if self.types.is_change_notifier(enclosing_type) {
                    if let Some(cn_sym) = self.enclosing_class_symbol(node) {
                        debug!(
                            ?node,
                            cn_sym_id = cn_sym.0,
                            "discovered ChangeNotifier emitter"
                        );
                        self.emitters.entry(cn_sym).or_default().push(node);
                    }
                }
            }
        }
    }

    /// Check if a field write is a reactive state mutation.
    fn check_field_emitter(&mut self, node: NodeId, _sym: Option<SymbolId>) {
        let field_name = self.written_field_name(node);

        // Riverpod StateNotifier: state = newValue
        if field_name.as_deref() == Some("state") {
            if let Some(enclosing_type) = self.enclosing_class_type(node) {
                if self.types.is_state_notifier(enclosing_type)
                    || self.types.is_riverpod_notifier(enclosing_type)
                {
                    if let Some(notifier_sym) = self.enclosing_class_symbol(node) {
                        debug!(
                            ?node,
                            notifier_sym_id = notifier_sym.0,
                            "discovered StateNotifier emitter"
                        );
                        self.emitters.entry(notifier_sym).or_default().push(node);
                        return;
                    }
                }
            }
        }

        // ValueNotifier: value = newValue
        if field_name.as_deref() == Some("value") {
            if let Some(enclosing_type) = self.enclosing_class_type(node) {
                if self.types.is_value_notifier(enclosing_type) {
                    if let Some(vn_sym) = self.enclosing_class_symbol(node) {
                        debug!(
                            ?node,
                            vn_sym_id = vn_sym.0,
                            "discovered ValueNotifier emitter"
                        );
                        self.emitters.entry(vn_sym).or_default().push(node);
                    }
                }
            }
        }
    }

    // -- Phase 2: discover subscribers ------------------------------------

    fn phase2_discover_subscribers(&mut self) {
        let nodes: Vec<(NodeId, NodeKind, Option<SymbolId>)> = self
            .graph
            .iter_nodes()
            .map(|n| (n.id, n.kind, n.symbol))
            .collect();

        for (nid, kind, sym) in &nodes {
            match kind {
                NodeKind::MethodCall => {
                    self.check_method_subscriber(*nid, *sym);
                }
                NodeKind::ConstructorCall => {
                    self.check_constructor_subscriber(*nid, *sym);
                }
                _ => {}
            }
        }
    }

    /// Check if a method call is a reactive subscription.
    fn check_method_subscriber(&mut self, node: NodeId, _sym: Option<SymbolId>) {
        let method_name = self.method_name_of(node);

        // Stream.listen()
        if method_name.as_deref() == Some("listen") {
            if let Some(receiver_type) = self.receiver_type(node) {
                if self.types.is_stream(receiver_type) {
                    if let Some(channel) = self.receiver_symbol(node) {
                        debug!(
                            ?node,
                            channel_id = channel.0,
                            "discovered stream subscriber"
                        );
                        self.subscribers.entry(channel).or_default().push(node);
                        return;
                    }
                }
            }
        }

        // Riverpod: ref.watch(provider)
        if method_name.as_deref() == Some("watch") {
            if let Some(provider_sym) = self.first_arg_symbol(node) {
                debug!(
                    ?node,
                    provider_sym_id = provider_sym.0,
                    "discovered ref.watch subscriber"
                );
                self.subscribers.entry(provider_sym).or_default().push(node);
                return;
            }
        }

        // Provider.of<T>(context) / context.watch<T>()
        if matches!(method_name.as_deref(), Some("of" | "watch" | "read")) {
            // Check if this is a Provider.of or context.watch pattern.
            if let Some(provider_sym) = self.generic_type_arg_symbol(node) {
                debug!(
                    ?node,
                    provider_sym_id = provider_sym.0,
                    "discovered Provider.of/watch subscriber"
                );
                self.subscribers.entry(provider_sym).or_default().push(node);
            }
        }
    }

    /// Check if a constructor call creates a reactive builder widget.
    fn check_constructor_subscriber(&mut self, node: NodeId, sym: Option<SymbolId>) {
        let Some(constructor_sym) = sym else { return };
        let constructor_name = self.graph.symbol(constructor_sym).canonical.clone();

        // StreamBuilder(stream: ..., builder: ...)
        if constructor_name.contains("StreamBuilder") {
            if let Some(stream_sym) = self.named_arg_symbol(node, "stream") {
                debug!(
                    ?node,
                    stream_sym_id = stream_sym.0,
                    "discovered StreamBuilder subscriber"
                );
                self.subscribers.entry(stream_sym).or_default().push(node);
                return;
            }
        }

        // BlocBuilder / BlocListener / BlocConsumer
        if constructor_name.contains("BlocBuilder")
            || constructor_name.contains("BlocListener")
            || constructor_name.contains("BlocConsumer")
        {
            if let Some(bloc_sym) = self.generic_type_arg_symbol(node) {
                debug!(
                    ?node,
                    bloc_sym_id = bloc_sym.0,
                    "discovered BlocBuilder subscriber"
                );
                self.subscribers.entry(bloc_sym).or_default().push(node);
                return;
            }
        }

        // ValueListenableBuilder
        if constructor_name.contains("ValueListenableBuilder") {
            if let Some(vl_sym) = self.named_arg_symbol(node, "valueListenable") {
                debug!(
                    ?node,
                    vl_sym_id = vl_sym.0,
                    "discovered ValueListenableBuilder subscriber"
                );
                self.subscribers.entry(vl_sym).or_default().push(node);
            }
        }
    }

    // -- Phase 3: discover build methods ----------------------------------

    fn phase3_discover_build_methods(&mut self) {
        let nodes: Vec<(NodeId, NodeKind, Option<SymbolId>)> = self
            .graph
            .iter_nodes()
            .map(|n| (n.id, n.kind, n.symbol))
            .collect();

        for (nid, kind, sym) in &nodes {
            if *kind != NodeKind::MethodDecl && *kind != NodeKind::BuildMethod {
                continue;
            }
            let Some(method_sym) = sym else { continue };
            let method_name = &self.graph.symbol(*method_sym).canonical;

            // Is this a build() method?
            if !method_name.ends_with(".build") && !method_name.ends_with("#build") {
                continue;
            }

            // Is the enclosing class a reactive widget?
            if let Some(class_type) = self.enclosing_class_type(*nid) {
                if self.types.is_consumer_widget(class_type) {
                    // Find which providers this build method watches.
                    let watched = self.find_watched_providers(*nid);
                    for provider in watched {
                        debug!(
                            ?nid,
                            provider_id = provider.0,
                            "discovered build method watching provider"
                        );
                        self.build_methods.entry(provider).or_default().push(*nid);
                    }
                }
            }
        }
    }

    /// Scan a build() method body for ref.watch() calls and return the
    /// watched provider symbols.
    fn find_watched_providers(&self, build_node: NodeId) -> Vec<SymbolId> {
        let mut watched = Vec::new();
        // Walk CFG successors within the same procedure to find watch calls.
        let mut stack = vec![build_node];
        let mut visited = rustc_hash::FxHashSet::default();

        while let Some(cur) = stack.pop() {
            if !visited.insert(cur) {
                continue;
            }
            let node = self.graph.node(cur);
            // Stay within the same procedure.
            if node.procedure != self.graph.node(build_node).procedure && node.procedure.is_some() {
                continue;
            }

            // Check for ref.watch() calls.
            if node.kind == NodeKind::MethodCall {
                let method = self.method_name_of_immut(cur);
                if method.as_deref() == Some("watch") {
                    if let Some(provider) = self.first_arg_symbol_immut(cur) {
                        watched.push(provider);
                    }
                }
            }

            // Follow CFG edges to continue the walk.
            for edge in self.graph.out_edges(cur, EdgeKindTag::Cfg) {
                stack.push(edge.dst);
            }
        }

        watched
    }

    // -- Phase 4: wire edges ----------------------------------------------

    fn phase4_wire_edges(&mut self) -> usize {
        let mut count = 0usize;

        // Collect all channel/provider symbols that have both emitters and
        // subscribers (or build methods).
        let all_channels: Vec<SymbolId> = self.emitters.keys().copied().collect();

        for channel in all_channels {
            let emit_nodes: SmallVec<[NodeId; 8]> = self
                .emitters
                .get(&channel)
                .map(|v| v.iter().copied().collect())
                .unwrap_or_default();

            let sub_nodes: SmallVec<[NodeId; 8]> = self
                .subscribers
                .get(&channel)
                .map(|v| v.iter().copied().collect())
                .unwrap_or_default();

            let build_nodes: SmallVec<[NodeId; 4]> = self
                .build_methods
                .get(&channel)
                .map(|v| v.iter().copied().collect())
                .unwrap_or_default();

            // ReactiveFlow: emitter → subscriber
            for &emitter in &emit_nodes {
                for &subscriber in &sub_nodes {
                    self.graph.add_edge(
                        emitter,
                        subscriber,
                        EdgeKind::Rdg(RdgEdge::ReactiveFlow { channel }),
                    );
                    count += 1;
                }
            }

            // RebuildTrigger: emitter → build method
            for &emitter in &emit_nodes {
                for &build in &build_nodes {
                    let widget = self.enclosing_class_symbol_of(build).unwrap_or(channel);
                    self.graph.add_edge(
                        emitter,
                        build,
                        EdgeKind::Rdg(RdgEdge::RebuildTrigger { widget }),
                    );
                    count += 1;
                }
            }

            // ReactiveWrite: emitter (as writer)
            for &emitter in &emit_nodes {
                self.graph.add_edge(
                    emitter,
                    emitter, // self-loop — the write itself is the anchor
                    EdgeKind::Rdg(RdgEdge::ReactiveWrite { provider: channel }),
                );
                count += 1;
            }

            // ReactiveRead: subscriber (as reader)
            for &subscriber in &sub_nodes {
                self.graph.add_edge(
                    subscriber,
                    subscriber,
                    EdgeKind::Rdg(RdgEdge::ReactiveRead { provider: channel }),
                );
                count += 1;
            }
        }

        count
    }

    // =====================================================================
    // CPG navigation helpers
    // =====================================================================

    /// Get the method name from a MethodCall node by walking AST children
    /// to find the selector.
    fn method_name_of(&self, node: NodeId) -> Option<String> {
        self.method_name_of_immut(node)
    }

    fn method_name_of_immut(&self, node: NodeId) -> Option<String> {
        let n = self.graph.node(node);
        if let Some(sym) = n.symbol {
            let canonical = &self.graph.symbol(sym).canonical;
            // Extract the last segment: "...#Class.method" → "method"
            canonical.rsplit_once('.').map(|(_, m)| m.to_owned())
        } else {
            None
        }
    }

    /// Get the resolved type of the receiver of a method call. Walks the
    /// first AST child (slot 0 = receiver).
    fn receiver_type(&self, node: NodeId) -> Option<crate::cpg::TypeId> {
        for edge in self.graph.out_edges(node, EdgeKindTag::Ast) {
            if matches!(
                edge.kind,
                EdgeKind::Ast(crate::cpg::AstEdge::Child { slot: 0 })
            ) {
                let receiver = self.graph.node(edge.dst);
                if let Some(TypeRef::Resolved(tid)) = &receiver.type_ref {
                    return Some(*tid);
                }
            }
        }
        None
    }

    /// Get the symbol of the receiver sub-tree.
    fn receiver_symbol(&self, node: NodeId) -> Option<SymbolId> {
        for edge in self.graph.out_edges(node, EdgeKindTag::Ast) {
            if matches!(
                edge.kind,
                EdgeKind::Ast(crate::cpg::AstEdge::Child { slot: 0 })
            ) {
                return self.graph.node(edge.dst).symbol;
            }
        }
        None
    }

    /// Get the symbol of the first positional argument (slot 2 after
    /// receiver and selector).
    fn first_arg_symbol(&self, node: NodeId) -> Option<SymbolId> {
        self.first_arg_symbol_immut(node)
    }

    fn first_arg_symbol_immut(&self, node: NodeId) -> Option<SymbolId> {
        for edge in self.graph.out_edges(node, EdgeKindTag::Ast) {
            if matches!(
                edge.kind,
                EdgeKind::Ast(crate::cpg::AstEdge::Child { slot: 2 })
            ) {
                return self.graph.node(edge.dst).symbol;
            }
        }
        None
    }

    /// Get the symbol of a named argument (by scanning AST children for a
    /// matching identifier).
    fn named_arg_symbol(&self, node: NodeId, _name: &str) -> Option<SymbolId> {
        // Simplified: in the full implementation, we would walk AST children
        // looking for a NamedExpression with the matching label. For now,
        // fall back to the first argument with a symbol.
        self.first_arg_symbol(node)
    }

    /// Get the TypeId from a generic type argument on a constructor or
    /// static method call. Used for `BlocBuilder<MyBloc, MyState>` to
    /// extract the `MyBloc` symbol.
    fn generic_type_arg_symbol(&mut self, node: NodeId) -> Option<SymbolId> {
        let n = self.graph.node(node);
        if let Some(TypeRef::Resolved(tid)) = &n.type_ref {
            let entry = self.types.get(*tid);
            if let Some(&first_arg) = entry.type_args.first() {
                let arg_entry = self.types.get(first_arg);
                // Look up the type's canonical name as a symbol.
                return Some(self.graph.intern_symbol(&arg_entry.canonical));
            }
        }
        None
    }

    /// Written field name for a FieldWrite node.
    fn written_field_name(&self, node: NodeId) -> Option<String> {
        let n = self.graph.node(node);
        if let Some(sym) = n.symbol {
            let canonical = &self.graph.symbol(sym).canonical;
            canonical.rsplit_once('.').map(|(_, f)| f.to_owned())
        } else {
            None
        }
    }

    /// Resolved type of the enclosing class for a node.
    fn enclosing_class_type(&self, node: NodeId) -> Option<crate::cpg::TypeId> {
        // Walk up via the `procedure` pointer, then find the class decl.
        let proc_entry = self.graph.node(node).procedure?;
        // The procedure's parent (via incoming AST edge) is the class.
        for edge in self.graph.in_edges(proc_entry, EdgeKindTag::Ast) {
            let parent = self.graph.node(edge.src);
            if matches!(parent.kind, NodeKind::ClassDecl | NodeKind::MixinDecl) {
                if let Some(TypeRef::Resolved(tid)) = &parent.type_ref {
                    return Some(*tid);
                }
            }
        }
        None
    }

    /// Symbol of the enclosing class.
    fn enclosing_class_symbol(&mut self, node: NodeId) -> Option<SymbolId> {
        self.enclosing_class_symbol_of(node)
    }

    fn enclosing_class_symbol_of(&self, node: NodeId) -> Option<SymbolId> {
        let proc_entry = self.graph.node(node).procedure?;
        for edge in self.graph.in_edges(proc_entry, EdgeKindTag::Ast) {
            let parent = self.graph.node(edge.src);
            if matches!(parent.kind, NodeKind::ClassDecl | NodeKind::MixinDecl) {
                return parent.symbol;
            }
        }
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpg::AstEdge;
    use crate::frontend::types::DartTypeDesc;

    /// Build a minimal CPG with a StreamController.add() → stream.listen()
    /// pattern and verify that the RDG builder connects them.
    #[test]
    fn stream_controller_add_to_listen() {
        let mut g = CodeGraph::new();
        let mut types = TypeArena::new();

        // Register the StreamController type.
        let sc_type = types.intern_from_desc(&DartTypeDesc {
            name: "StreamController".into(),
            library: "dart:async".into(),
            type_args: vec![DartTypeDesc {
                name: "String".into(),
                library: "dart:core".into(),
                type_args: vec![],
                is_nullable: false,
                supertypes: vec![],
            }],
            is_nullable: false,
            supertypes: vec!["dart:async#StreamSink".into()],
        });
        let stream_type = types.intern_from_desc(&DartTypeDesc {
            name: "Stream".into(),
            library: "dart:async".into(),
            type_args: vec![],
            is_nullable: false,
            supertypes: vec![],
        });

        let f = g.intern_file("test.dart");
        let channel_sym = g.intern_symbol("test.dart#_controller");

        // --- Emitter side: _controller.add(x) ---
        let emit_receiver = g.add_node(NodeKind::Identifier, f, 0..11);
        g.node_mut(emit_receiver).symbol = Some(channel_sym);
        g.node_mut(emit_receiver).type_ref = Some(TypeRef::Resolved(sc_type));

        let add_sym = g.intern_symbol("dart:async#StreamController.add");
        let emit_call = g.add_node(NodeKind::MethodCall, f, 0..20);
        g.node_mut(emit_call).symbol = Some(add_sym);
        g.add_edge(
            emit_call,
            emit_receiver,
            EdgeKind::Ast(AstEdge::Child { slot: 0 }),
        );

        // --- Subscriber side: _controller.stream.listen(cb) ---
        let sub_receiver = g.add_node(NodeKind::Identifier, f, 30..41);
        g.node_mut(sub_receiver).symbol = Some(channel_sym);
        g.node_mut(sub_receiver).type_ref = Some(TypeRef::Resolved(stream_type));

        let listen_sym = g.intern_symbol("dart:async#Stream.listen");
        let listen_call = g.add_node(NodeKind::MethodCall, f, 30..55);
        g.node_mut(listen_call).symbol = Some(listen_sym);
        g.add_edge(
            listen_call,
            sub_receiver,
            EdgeKind::Ast(AstEdge::Child { slot: 0 }),
        );

        let count = build_rdg(&mut g, &types);

        // Expect at least one ReactiveFlow edge from emitter to subscriber.
        let rdg_edges: Vec<_> = g.out_edges(emit_call, EdgeKindTag::Rdg).collect();
        assert!(
            rdg_edges.iter().any(
                |e| matches!(e.kind, EdgeKind::Rdg(RdgEdge::ReactiveFlow { .. }))
                    && e.dst == listen_call
            ),
            "expected ReactiveFlow edge from add() to listen(), got {:?}",
            rdg_edges
        );
        assert!(count > 0, "expected at least one RDG edge");
    }
}
