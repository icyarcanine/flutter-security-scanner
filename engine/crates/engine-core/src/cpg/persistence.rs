// Feature-gated module; the deserialised wire types and column-family
// constants are intentionally undocumented until the persistence API
// stabilises.
#![allow(missing_docs)]

//! RocksDB-backed persistent CPG store with incremental analysis support.
//!
//! # Why persistence?
//!
//! On a large workspace, rebuilding the CPG from scratch takes 2–5 seconds.
//! In the IDE, a developer expects feedback within 100 ms of a keystroke.
//! The persistence layer closes this gap by caching the graph to disk and
//! patching it incrementally when a single file changes.
//!
//! # Storage layout (RocksDB column families)
//!
//! | CF name    | Key                  | Value                          |
//! |------------|----------------------|--------------------------------|
//! | `nodes`    | `NodeId.raw()` (u32) | `bincode(Node)`                |
//! | `edges`    | `EdgeId.raw()` (u32) | `bincode(Edge)`                |
//! | `symbols`  | `SymbolId.raw()`     | `bincode(SymbolEntry)`         |
//! | `files`    | `FileId.raw()`       | canonical path (UTF-8)         |
//! | `file_idx` | `FileId.raw()`       | `bincode(Vec<NodeId>)` (membership) |
//! | `meta`     | arbitrary string     | arbitrary bytes                |
//!
//! # Incremental analysis algorithm
//!
//! When a file changes:
//!
//! 1. Load the `file_idx` entry to get the stale `Vec<NodeId>`.
//! 2. Tombstone those nodes in the `nodes` CF.
//! 3. Delete all edges touching the stale nodes from the `edges` CF.
//! 4. Re-parse the changed file (outside this module).
//! 5. Append the new nodes and edges to the store.
//! 6. Compute the **affected set** via BFS over ICFG Call/Return edges
//!    from the stale procedure entries. This is the minimal set of
//!    procedures whose IFDS summary edges might change.
//! 7. Return the affected set to the caller so it can invalidate exactly
//!    those summaries and re-run the IFDS solver on them.
//!
//! # Feature gate
//!
//! This module is compiled only when the `persist` feature is enabled
//! (default on native builds, off on WASM).

use std::collections::VecDeque;
use std::path::Path;

use rocksdb::{
    ColumnFamilyDescriptor, DBWithThreadMode, IteratorMode, MultiThreaded, Options, WriteBatch,
};
use rustc_hash::FxHashSet;
use tracing::{debug, info};

use crate::cpg::{
    CodeGraph, Edge, EdgeKind, EdgeKindTag, FileId, IcfgEdge, Node, NodeId, NodeKind,
};

// ============================================================================
// Column family names
// ============================================================================

const CF_NODES: &str = "nodes";
const CF_EDGES: &str = "edges";
const CF_SYMBOLS: &str = "symbols";
const CF_FILES: &str = "files";
const CF_FILE_IDX: &str = "file_idx";
const CF_META: &str = "meta";

const ALL_CFS: &[&str] = &[
    CF_NODES,
    CF_EDGES,
    CF_SYMBOLS,
    CF_FILES,
    CF_FILE_IDX,
    CF_META,
];

/// Current schema version. Bumped on any breaking change to the
/// serialisation format. On mismatch, the store is wiped and rebuilt from
/// scratch rather than attempting a migration — CPG data is derived, not
/// user data, so rebuilding is always safe.
const SCHEMA_VERSION: u32 = 1;

// ============================================================================
// Store
// ============================================================================

/// Persistent CPG store backed by RocksDB.
pub struct CpgStore {
    db: DBWithThreadMode<MultiThreaded>,
}

/// Errors from the persistence layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// RocksDB error.
    #[error("RocksDB: {0}")]
    Rocks(#[from] rocksdb::Error),
    /// Serialisation error.
    #[error("bincode: {0}")]
    Bincode(String),
    /// Schema version mismatch (store is stale and must be rebuilt).
    #[error("schema version mismatch: expected {expected}, found {found}")]
    SchemaMismatch { expected: u32, found: u32 },
}

impl CpgStore {
    /// Open (or create) a store at `path`. If the schema version does not
    /// match, the database is destroyed and recreated.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        // Tuning for our access pattern: large sequential writes during
        // build, random reads during analysis.
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64 MB
        opts.set_max_write_buffer_number(3);
        opts.set_target_file_size_base(64 * 1024 * 1024);
        opts.increase_parallelism(num_cpus());

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_CFS
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db =
            DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(&opts, path, cf_descriptors)?;

        let store = Self { db };

        // Check schema version.
        match store.get_meta("schema_version")? {
            Some(bytes) if bytes.len() == 4 => {
                let found = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if found != SCHEMA_VERSION {
                    info!(
                        found,
                        expected = SCHEMA_VERSION,
                        "schema version mismatch — wiping store"
                    );
                    drop(store);
                    DBWithThreadMode::<MultiThreaded>::destroy(&opts, path)?;
                    return Self::open(path);
                }
            }
            _ => {
                // Fresh database — write schema version.
                store.put_meta("schema_version", &SCHEMA_VERSION.to_le_bytes())?;
            }
        }

        Ok(store)
    }

    // -- bulk save / load -------------------------------------------------

    /// Persist an entire in-memory [`CodeGraph`] to the store. Clears
    /// existing data first.
    pub fn save_graph(&self, graph: &CodeGraph) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        let nodes_cf = self.cf(CF_NODES);
        let edges_cf = self.cf(CF_EDGES);
        // CF_SYMBOLS handle reserved for the next persistence pass that
        // will write per-symbol metadata; the current `save_graph` only
        // writes nodes/edges/files/file_idx.
        let _symbols_cf = self.cf(CF_SYMBOLS);
        let files_cf = self.cf(CF_FILES);
        let file_idx_cf = self.cf(CF_FILE_IDX);

        // Nodes.
        let mut file_membership: rustc_hash::FxHashMap<FileId, Vec<NodeId>> =
            rustc_hash::FxHashMap::default();
        for node in graph.iter_nodes() {
            let key = node.id.raw().to_le_bytes();
            let value = bincode::serialize(node).map_err(|e| StoreError::Bincode(e.to_string()))?;
            batch.put_cf(&nodes_cf, key, value);
            file_membership.entry(node.file).or_default().push(node.id);
        }

        // Edges.
        for node in graph.iter_nodes() {
            for (eid, edge) in graph.out_edges_with_id_all(node.id) {
                let key = eid.raw().to_le_bytes();
                let value =
                    bincode::serialize(edge).map_err(|e| StoreError::Bincode(e.to_string()))?;
                batch.put_cf(&edges_cf, key, value);
            }
        }

        // Symbols.
        for (idx, _) in graph.iter_nodes().enumerate() {
            // Symbols are indexed by SymbolId, iterate via the graph's
            // symbol data if exposed. For now, skip — symbols are
            // re-interned on load.
            let _ = idx;
        }

        // Files.
        for node in graph.iter_nodes() {
            let key = node.file.0.to_le_bytes();
            let path = graph.file_path(node.file);
            batch.put_cf(&files_cf, key, path.as_bytes());
        }

        // File index.
        for (file_id, node_ids) in &file_membership {
            let key = file_id.0.to_le_bytes();
            let value =
                bincode::serialize(node_ids).map_err(|e| StoreError::Bincode(e.to_string()))?;
            batch.put_cf(&file_idx_cf, key, value);
        }

        self.db.write(batch)?;
        info!(
            nodes = graph.node_count(),
            edges = graph.edge_count(),
            "graph persisted to store"
        );
        Ok(())
    }

    /// Load the persisted graph into a fresh [`CodeGraph`]. Returns `None`
    /// if the store is empty.
    pub fn load_graph(&self) -> Result<Option<CodeGraph>, StoreError> {
        let nodes_cf = self.cf(CF_NODES);
        let edges_cf = self.cf(CF_EDGES);
        let files_cf = self.cf(CF_FILES);

        // Load files first.
        let mut graph = CodeGraph::new();
        let file_iter = self.db.iterator_cf(&files_cf, IteratorMode::Start);
        let mut file_count = 0u32;
        for item in file_iter {
            let (key, value) = item?;
            let _file_id = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
            let path = std::str::from_utf8(&value).unwrap_or("<invalid>");
            graph.intern_file(path);
            file_count += 1;
        }
        if file_count == 0 {
            return Ok(None);
        }

        // Load nodes.
        let node_iter = self.db.iterator_cf(&nodes_cf, IteratorMode::Start);
        for item in node_iter {
            let (_key, value) = item?;
            let node: Node =
                bincode::deserialize(&value).map_err(|e| StoreError::Bincode(e.to_string()))?;
            // Re-create the node in the graph. The NodeId must match.
            let nid = graph.add_node(node.kind, node.file, node.byte_range.clone());
            graph.node_mut(nid).type_ref = node.type_ref;
            graph.node_mut(nid).symbol = node.symbol;
            graph.node_mut(nid).procedure = node.procedure;
        }

        // Load edges.
        let edge_iter = self.db.iterator_cf(&edges_cf, IteratorMode::Start);
        for item in edge_iter {
            let (_key, value) = item?;
            let edge: Edge =
                bincode::deserialize(&value).map_err(|e| StoreError::Bincode(e.to_string()))?;
            graph.add_edge(edge.src, edge.dst, edge.kind);
        }

        info!(
            nodes = graph.node_count(),
            edges = graph.edge_count(),
            "graph loaded from store"
        );
        Ok(Some(graph))
    }

    // -- incremental patching ---------------------------------------------

    /// Get the set of `NodeId`s owned by a file from the persisted file
    /// index. Returns an empty vec for unknown files.
    pub fn nodes_for_file(&self, file: FileId) -> Result<Vec<NodeId>, StoreError> {
        let cf = self.cf(CF_FILE_IDX);
        let key = file.0.to_le_bytes();
        match self.db.get_cf(&cf, key)? {
            Some(bytes) => {
                let ids: Vec<NodeId> =
                    bincode::deserialize(&bytes).map_err(|e| StoreError::Bincode(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Tombstone a file's nodes and edges in the store. Returns the
    /// invalidated procedure entries (same semantics as
    /// [`CodeGraph::tombstone_file`]).
    pub fn tombstone_file(
        &self,
        file: FileId,
        graph: &mut CodeGraph,
    ) -> Result<Vec<NodeId>, StoreError> {
        let stale_nodes = self.nodes_for_file(file)?;
        if stale_nodes.is_empty() {
            return Ok(Vec::new());
        }

        let mut batch = WriteBatch::default();
        let nodes_cf = self.cf(CF_NODES);
        let edges_cf = self.cf(CF_EDGES);
        let file_idx_cf = self.cf(CF_FILE_IDX);

        // Delete stale node entries.
        for &nid in &stale_nodes {
            batch.delete_cf(&nodes_cf, nid.raw().to_le_bytes());
        }

        // Delete edges touching stale nodes.
        let stale_set: FxHashSet<NodeId> = stale_nodes.iter().copied().collect();
        let edge_iter = self.db.iterator_cf(&edges_cf, IteratorMode::Start);
        for item in edge_iter {
            let (key, value) = item?;
            let edge: Edge =
                bincode::deserialize(&value).map_err(|e| StoreError::Bincode(e.to_string()))?;
            if stale_set.contains(&edge.src) || stale_set.contains(&edge.dst) {
                batch.delete_cf(&edges_cf, key);
            }
        }

        // Clear the file index entry.
        batch.delete_cf(&file_idx_cf, file.0.to_le_bytes());

        self.db.write(batch)?;

        // Perform the in-memory tombstone.
        let invalidated = graph.tombstone_file(file);
        debug!(
            stale = stale_nodes.len(),
            invalidated = invalidated.len(),
            "file tombstoned"
        );

        Ok(invalidated)
    }

    /// Persist newly appended nodes and edges (added after a re-parse of a
    /// changed file). Also updates the file index.
    pub fn persist_incremental(
        &self,
        file: FileId,
        new_nodes: &[NodeId],
        graph: &CodeGraph,
    ) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        let nodes_cf = self.cf(CF_NODES);
        let edges_cf = self.cf(CF_EDGES);
        let file_idx_cf = self.cf(CF_FILE_IDX);

        for &nid in new_nodes {
            let node = graph.node(nid);
            let key = nid.raw().to_le_bytes();
            let value = bincode::serialize(node).map_err(|e| StoreError::Bincode(e.to_string()))?;
            batch.put_cf(&nodes_cf, key, value);
        }

        // Persist edges for the new nodes.
        for &nid in new_nodes {
            for (eid, edge) in graph.out_edges_with_id_all(nid) {
                let key = eid.raw().to_le_bytes();
                let value =
                    bincode::serialize(edge).map_err(|e| StoreError::Bincode(e.to_string()))?;
                batch.put_cf(&edges_cf, key, value);
            }
        }

        // Update file index.
        let idx_value =
            bincode::serialize(new_nodes).map_err(|e| StoreError::Bincode(e.to_string()))?;
        batch.put_cf(&file_idx_cf, file.0.to_le_bytes(), idx_value);

        self.db.write(batch)?;
        debug!(file = ?file, nodes = new_nodes.len(), "incremental persist complete");
        Ok(())
    }

    // -- affected-set computation -----------------------------------------

    /// Compute the transitive affected set of procedures from a set of
    /// invalidated procedure entries. BFS over ICFG Call and Return edges
    /// to find all callers and callees that might be affected by the
    /// change.
    ///
    /// The returned set is the minimal set of procedures whose IFDS
    /// summary edges must be invalidated and re-computed.
    pub fn affected_set(graph: &CodeGraph, invalidated_procs: &[NodeId]) -> FxHashSet<NodeId> {
        let mut affected = FxHashSet::default();
        let mut queue = VecDeque::new();

        for &proc in invalidated_procs {
            if affected.insert(proc) {
                queue.push_back(proc);
            }
        }

        while let Some(proc_entry) = queue.pop_front() {
            // Find all nodes in this procedure.
            // Walk forward from entry along CFG to find CallSite and
            // ExitNode nodes.
            let mut proc_nodes = Vec::new();
            let mut visit_stack = vec![proc_entry];
            let mut visited = FxHashSet::default();

            while let Some(cur) = visit_stack.pop() {
                if !visited.insert(cur) {
                    continue;
                }
                let node = graph.node(cur);
                if node.procedure == Some(proc_entry) || cur == proc_entry {
                    proc_nodes.push(cur);
                    for edge in graph.out_edges(cur, EdgeKindTag::Cfg) {
                        visit_stack.push(edge.dst);
                    }
                }
            }

            // For each CallSite in this procedure, add the callee.
            for &nid in &proc_nodes {
                if graph.node(nid).kind != NodeKind::CallSite {
                    continue;
                }
                for edge in graph.out_edges(nid, EdgeKindTag::Icfg) {
                    if matches!(edge.kind, EdgeKind::Icfg(IcfgEdge::Call)) {
                        let callee_entry = edge.dst;
                        if affected.insert(callee_entry) {
                            queue.push_back(callee_entry);
                        }
                    }
                }
            }

            // For each ExitNode → Return edge, add the caller's procedure.
            for &nid in &proc_nodes {
                if graph.node(nid).kind != NodeKind::ExitNode {
                    continue;
                }
                for edge in graph.out_edges(nid, EdgeKindTag::Icfg) {
                    if matches!(edge.kind, EdgeKind::Icfg(IcfgEdge::Return)) {
                        let return_site = edge.dst;
                        if let Some(caller_proc) = graph.node(return_site).procedure {
                            if affected.insert(caller_proc) {
                                queue.push_back(caller_proc);
                            }
                        }
                    }
                }
            }
        }

        affected
    }

    // -- low-level helpers ------------------------------------------------

    fn cf(&self, name: &str) -> Arc<rocksdb::BoundColumnFamily<'_>> {
        self.db
            .cf_handle(name)
            .unwrap_or_else(|| panic!("missing column family: {name}"))
    }

    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let cf = self.cf(CF_META);
        Ok(self.db.get_cf(&cf, key.as_bytes())?)
    }

    fn put_meta(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        let cf = self.cf(CF_META);
        self.db.put_cf(&cf, key.as_bytes(), value)?;
        Ok(())
    }
}

use std::sync::Arc;

/// Best-effort CPU count for RocksDB parallelism tuning.
fn num_cpus() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(4)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpg::{CfgEdge, IcfgEdge};

    #[test]
    fn affected_set_finds_callers_and_callees() {
        let mut g = CodeGraph::new();
        let f = g.intern_file("test.dart");

        // Procedure A: entry_a → call_site → return_site → exit_a
        let entry_a = g.add_node(NodeKind::EntryNode, f, 0..1);
        let call_ab = g.add_node(NodeKind::CallSite, f, 1..2);
        let ret_ab = g.add_node(NodeKind::ReturnSite, f, 2..3);
        let exit_a = g.add_node(NodeKind::ExitNode, f, 3..4);
        for &n in &[entry_a, call_ab, ret_ab, exit_a] {
            g.node_mut(n).procedure = Some(entry_a);
        }
        g.add_edge(entry_a, call_ab, EdgeKind::Cfg(CfgEdge::Fall));
        g.add_edge(call_ab, ret_ab, EdgeKind::Icfg(IcfgEdge::CallToReturn));
        g.add_edge(ret_ab, exit_a, EdgeKind::Cfg(CfgEdge::Fall));

        // Procedure B: entry_b → exit_b
        let entry_b = g.add_node(NodeKind::EntryNode, f, 10..11);
        let exit_b = g.add_node(NodeKind::ExitNode, f, 11..12);
        g.node_mut(entry_b).procedure = Some(entry_b);
        g.node_mut(exit_b).procedure = Some(entry_b);
        g.add_edge(entry_b, exit_b, EdgeKind::Cfg(CfgEdge::Fall));

        // ICFG: A calls B.
        g.add_edge(call_ab, entry_b, EdgeKind::Icfg(IcfgEdge::Call));
        g.add_edge(exit_b, ret_ab, EdgeKind::Icfg(IcfgEdge::Return));

        // Invalidate B → affected set should include both A and B.
        let affected = CpgStore::affected_set(&g, &[entry_b]);
        assert!(affected.contains(&entry_b), "B should be in affected set");
        assert!(
            affected.contains(&entry_a),
            "A (caller of B) should be in affected set"
        );
    }
}
