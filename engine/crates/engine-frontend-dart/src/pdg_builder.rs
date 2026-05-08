//! Pass 5: PDG Builder — Intra-procedural Data Dependence.
//!
//! This module identifies def-use chains within each procedure.
//! It uses a standard Reaching Definitions analysis to determine which
//! variable assignment at point A reaches a use at point B.

use engine_core::cpg::{CodeGraph, EdgeKind, EdgeKindTag, NodeId, NodeKind, PdgEdge, SymbolId};
use rustc_hash::{FxHashMap, FxHashSet};

pub struct PdgBuilder<'g> {
    graph: &'g mut CodeGraph,
}

impl<'g> PdgBuilder<'g> {
    pub fn new(graph: &'g mut CodeGraph) -> Self {
        Self { graph }
    }

    pub fn build(&mut self) {
        let entries: Vec<NodeId> = self
            .graph
            .iter_nodes()
            .filter(|n| n.kind == NodeKind::EntryNode)
            .map(|n| n.id)
            .collect();

        for entry in entries {
            self.analyze_procedure(entry);
        }
    }

    fn analyze_procedure(&mut self, entry_id: NodeId) {
        let mut proc_nodes = Vec::new();
        let mut stack = vec![entry_id];
        let mut visited = FxHashSet::default();

        while let Some(cur) = stack.pop() {
            if !visited.insert(cur) {
                continue;
            }
            proc_nodes.push(cur);
            for edge in self.graph.out_edges(cur, EdgeKindTag::Cfg) {
                stack.push(edge.dst);
            }
        }

        // 1. GEN and KILL sets.
        // GEN: { node_id | node defines variable X }
        // KILL: { node_id | node re-defines variable X, killing previous reaching defs }
        let mut gen = FxHashMap::default();
        let mut kill = FxHashMap::default();
        let mut node_to_var = FxHashMap::default();

        for &nid in &proc_nodes {
            let node = self.graph.node(nid);
            if node.kind == NodeKind::Assign || node.kind == NodeKind::Parameter {
                if let Some(var) = self.get_defined_var(nid) {
                    gen.entry(nid)
                        .or_insert_with(FxHashSet::default)
                        .insert(nid);
                    node_to_var.insert(nid, var);

                    // KILL is all other nodes in this proc that define the same var.
                    let mut k_set = FxHashSet::default();
                    for &other in &proc_nodes {
                        if other != nid {
                            if let Some(other_var) = self.get_defined_var(other) {
                                if other_var == var {
                                    k_set.insert(other);
                                }
                            }
                        }
                    }
                    kill.insert(nid, k_set);
                }
            }
        }

        // 2. Fixed-point iteration for IN/OUT sets.
        let mut in_set: FxHashMap<NodeId, FxHashSet<NodeId>> = FxHashMap::default();
        let mut out_set: FxHashMap<NodeId, FxHashSet<NodeId>> = FxHashMap::default();

        let mut changed = true;
        while changed {
            changed = false;
            for &nid in &proc_nodes {
                // IN[n] = U OUT[p] for all p in predecessors(n)
                let mut new_in = FxHashSet::default();
                for edge in self.graph.in_edges(nid, EdgeKindTag::Cfg) {
                    if let Some(p_out) = out_set.get(&edge.src) {
                        for &def in p_out {
                            new_in.insert(def);
                        }
                    }
                }
                in_set.insert(nid, new_in.clone());

                // OUT[n] = GEN[n] U (IN[n] - KILL[n])
                let mut new_out = gen.get(&nid).cloned().unwrap_or_default();
                let k = kill.get(&nid);
                for &reaching in &new_in {
                    if k.map_or(true, |set| !set.contains(&reaching)) {
                        new_out.insert(reaching);
                    }
                }

                let old_out = out_set.entry(nid).or_default();
                if &new_out != old_out {
                    *old_out = new_out;
                    changed = true;
                }
            }
        }

        // 3. Link uses to reaching definitions.
        for &nid in &proc_nodes {
            if let Some(used_var) = self.get_used_var(nid) {
                if let Some(reaching_defs) = in_set.get(&nid) {
                    for &def_id in reaching_defs {
                        if node_to_var.get(&def_id) == Some(&used_var) {
                            self.graph.add_edge(
                                def_id,
                                nid,
                                EdgeKind::Pdg(PdgEdge::DataDep { var: used_var }),
                            );
                        }
                    }
                }
            }
        }
    }

    fn get_defined_var(&self, nid: NodeId) -> Option<SymbolId> {
        let node = self.graph.node(nid);
        match node.kind {
            NodeKind::Assign => {
                // In Dart assignments, the first AST child (slot 0) is the LHS (the definition).
                for edge in self.graph.out_edges(nid, EdgeKindTag::Ast) {
                    if matches!(
                        edge.kind,
                        EdgeKind::Ast(engine_core::cpg::AstEdge::Child { slot: 0 })
                    ) {
                        return self.graph.node(edge.dst).symbol;
                    }
                }
            }
            NodeKind::Parameter => return node.symbol,
            _ => {}
        }
        None
    }

    fn get_used_var(&self, nid: NodeId) -> Option<SymbolId> {
        let node = self.graph.node(nid);
        if node.kind == NodeKind::Identifier {
            // An identifier is a USE if it is NOT the LHS of an assignment.
            // We check the parent node via incoming AST edges.
            for edge in self.graph.in_edges(nid, EdgeKindTag::Ast) {
                let parent = self.graph.node(edge.src);
                if parent.kind == NodeKind::Assign {
                    if let EdgeKind::Ast(engine_core::cpg::AstEdge::Child { slot }) = edge.kind {
                        if slot == 0 {
                            // This is the definition site, not a use.
                            return None;
                        }
                    }
                }
            }
            return node.symbol;
        }
        None
    }
}
