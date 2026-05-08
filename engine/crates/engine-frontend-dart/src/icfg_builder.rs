//! Pass 4: ICFG Builder — Inter-procedural Call Graph.
//!
//! This module stitches individual CFGs together. It connects `CallSite`
//! nodes to the `EntryNode` of their target procedures, and `ExitNode`
//! back to `ReturnSite`. This is the infrastructure for the IFDS solver.

use engine_core::cpg::{CodeGraph, EdgeKind, EdgeKindTag, IcfgEdge, NodeId, NodeKind};
use tracing::{debug, warn};

pub struct IcfgBuilder<'g> {
    graph: &'g mut CodeGraph,
}

impl<'g> IcfgBuilder<'g> {
    pub fn new(graph: &'g mut CodeGraph) -> Self {
        Self { graph }
    }

    pub fn build(&mut self) {
        // Optimization: Map EntryNode -> ExitNode once.
        let mut exit_map = rustc_hash::FxHashMap::default();
        for node in self.graph.iter_nodes() {
            if node.kind == NodeKind::ExitNode {
                if let Some(entry_id) = node.procedure {
                    exit_map.insert(entry_id, node.id);
                }
            }
        }

        let call_sites: Vec<NodeId> = self
            .graph
            .iter_nodes()
            .filter(|n| n.kind == NodeKind::MethodCall || n.kind == NodeKind::Call)
            .map(|n| n.id)
            .collect();

        for call in call_sites {
            self.link_call_site(call, &exit_map);
        }
    }

    fn link_call_site(
        &mut self,
        call_id: NodeId,
        exit_map: &rustc_hash::FxHashMap<NodeId, NodeId>,
    ) {
        let symbol = self.graph.node(call_id).symbol;

        let callee_entry = if let Some(sym_id) = symbol {
            self.graph.symbol(sym_id).decl
        } else {
            None
        };

        let Some(callee_entry_id) = callee_entry else {
            return;
        };

        let mut return_site_id = None;
        for edge in self.graph.out_edges(call_id, EdgeKindTag::Icfg) {
            if matches!(edge.kind, EdgeKind::Icfg(IcfgEdge::CallToReturn)) {
                return_site_id = Some(edge.dst);
                break;
            }
        }

        let Some(ret_id) = return_site_id else { return };

        self.graph
            .add_edge(call_id, callee_entry_id, EdgeKind::Icfg(IcfgEdge::Call));

        if let Some(&exit_id) = exit_map.get(&callee_entry_id) {
            self.graph
                .add_edge(exit_id, ret_id, EdgeKind::Icfg(IcfgEdge::Return));
        }
    }
}
