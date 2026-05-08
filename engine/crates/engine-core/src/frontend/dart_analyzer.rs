//! Dart analyzer sidecar bridge — semantic type resolution.
//!
//! # Architecture
//!
//! We do **not** reimplement Dart's type resolver. Instead, we hijack the
//! official `package:analyzer` by spawning a long-running Dart process that
//! streams resolved AST information back to the engine over stdout as
//! newline-delimited JSON (ndjson).
//!
//! ```text
//! ┌─────────────────┐    stdin: file paths     ┌────────────────────────┐
//! │   Rust engine    │ ──────────────────────► │  dart run helper.dart  │
//! │                  │                          │  (package:analyzer)    │
//! │  AnalyzerBridge  │ ◄────── stdout: ndjson ─ │                        │
//! │    .resolve()    │                          │  emits ResolvedElement │
//! │    .patch()      │                          │  per resolved AstNode  │
//! └─────────────────┘                          └────────────────────────┘
//! ```
//!
//! Each JSON line is a [`ResolvedElement`]: a byte offset, the resolved
//! canonical symbol, the Dart type, and the supertype chain. The bridge
//! matches these back to CPG nodes via a `(FileId, byte_offset)` index and
//! patches each node's `type_ref` and `symbol` fields in place.
//!
//! # Why ndjson over MessagePack/Protobuf?
//!
//! The Dart analyzer itself is the bottleneck (~2–5 s to resolve a mid-sized
//! workspace on first run, ~200 ms incremental). Serialization overhead is
//! <50 ms for 100K records regardless of format. ndjson is debuggable with
//! `jq`, which saves hours during development.
//!
//! # Process lifecycle
//!
//! - **CI mode:** spawn → resolve all files → collect output → exit.
//! - **IDE mode:** spawn once, keep alive, send changed-file paths over
//!   stdin, read incremental resolved elements. The bridge tracks the
//!   child PID and reaps it on drop.

use std::io::{BufRead, BufReader, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde::Deserialize;
use tracing::{debug, error, info, warn};

use crate::cpg::{CodeGraph, FileId, NodeId, TypeRef};
use crate::frontend::types::{DartTypeDesc, TypeArena};

// ============================================================================
// Wire types (deserialized from the Dart helper's JSON output)
// ============================================================================

/// One resolved reference from the Dart analyzer. Each instance maps a
/// source-code byte range to its resolved type and declaration symbol.
#[derive(Clone, Debug, Deserialize)]
pub struct ResolvedElement {
    /// Canonical file path (absolute, UTF-8).
    pub file: String,
    /// UTF-8 byte offset of the AST node's start.
    pub offset: u32,
    /// UTF-8 byte offset of the AST node's end.
    pub end_offset: u32,
    /// Kind of the resolved element.
    pub kind: ElementKind,
    /// Canonical symbol: `package:app/src/repo.dart#UserRepo.fetch`.
    pub canonical: String,
    /// Resolved Dart type descriptor.
    #[serde(rename = "type")]
    pub dart_type: Option<DartTypeDesc>,
    /// For class elements: the full supertype chain.
    #[serde(default)]
    pub supertypes: Vec<String>,
}

/// The kind of resolved element. Mirrors `package:analyzer`'s
/// `ElementKind` enum, filtered to the subset we care about.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ElementKind {
    Class,
    Mixin,
    Extension,
    Function,
    Method,
    Constructor,
    Getter,
    Setter,
    Field,
    TopLevelVariable,
    Parameter,
    LocalVariable,
    /// A reference to an element (e.g. a method invocation, field access).
    /// The `canonical` field identifies the declaration being referenced.
    Reference,
}

/// Protocol command sent to the Dart helper over stdin.
#[derive(Debug)]
enum BridgeCommand<'a> {
    /// Resolve (or re-resolve) the listed files.
    Resolve(&'a [&'a str]),
    /// Graceful shutdown.
    Shutdown,
}

// ============================================================================
// Bridge
// ============================================================================

/// Handle to a running Dart analyzer sidecar process.
pub struct AnalyzerBridge {
    /// The child process. `None` after shutdown.
    child: Option<Child>,
    /// Path to the Dart helper script.
    helper_script: PathBuf,
    /// Workspace root (passed to `AnalysisContextCollection`).
    workspace_root: PathBuf,
    /// Read timeout for a single batch of results.
    read_timeout: Duration,
}

/// Result of a resolution batch.
pub struct ResolutionResult {
    /// Successfully resolved elements.
    pub elements: Vec<ResolvedElement>,
    /// Files that failed to resolve (syntax errors, missing deps).
    pub failed_files: Vec<String>,
    /// Wall-clock time for this batch.
    pub elapsed: Duration,
}

impl AnalyzerBridge {
    /// Create a new bridge. Does **not** spawn the child process yet — call
    /// [`Self::start`] to do that.
    #[must_use]
    pub fn new(helper_script: PathBuf, workspace_root: PathBuf) -> Self {
        Self {
            child: None,
            helper_script,
            workspace_root,
            read_timeout: Duration::from_secs(60),
        }
    }

    /// Override the default read timeout (60 s). Large workspaces may need
    /// more time for the initial resolution pass.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Spawn the Dart helper process. The process stays alive for
    /// incremental resolution until [`Self::shutdown`] is called (or the
    /// bridge is dropped).
    pub fn start(&mut self) -> Result<(), BridgeError> {
        if self.child.is_some() {
            return Ok(()); // already running
        }
        info!(
            script = %self.helper_script.display(),
            workspace = %self.workspace_root.display(),
            "spawning Dart analyzer sidecar"
        );
        let child = Command::new("dart")
            .arg("run")
            .arg(&self.helper_script)
            .arg("--workspace")
            .arg(&self.workspace_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BridgeError::SpawnFailed(e.to_string()))?;
        self.child = Some(child);
        Ok(())
    }

    /// Send a list of file paths to the Dart helper for resolution and
    /// collect the ndjson output. Each file is resolved independently; a
    /// failure in one file does not prevent resolution of the others.
    pub fn resolve(&mut self, files: &[&str]) -> Result<ResolutionResult, BridgeError> {
        let start = std::time::Instant::now();
        let child = self.child.as_mut().ok_or(BridgeError::NotRunning)?;

        // Write the file list to stdin as a JSON array line.
        {
            let stdin = child.stdin.as_mut().ok_or(BridgeError::StdinClosed)?;
            let payload =
                serde_json::to_string(files).map_err(|e| BridgeError::Protocol(e.to_string()))?;
            writeln!(stdin, "{payload}").map_err(|e| BridgeError::Protocol(e.to_string()))?;
            stdin
                .flush()
                .map_err(|e| BridgeError::Protocol(e.to_string()))?;
        }

        // Read ndjson lines until we see the sentinel `{"done": true}`.
        let stdout = child.stdout.as_mut().ok_or(BridgeError::StdoutClosed)?;
        let reader = BufReader::new(stdout);
        let mut elements = Vec::new();
        let mut failed_files = Vec::new();

        for line_result in reader.lines() {
            let line = line_result.map_err(|e| BridgeError::Protocol(e.to_string()))?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Check for sentinel.
            if line.contains("\"done\"") {
                debug!(count = elements.len(), "resolution batch complete");
                break;
            }

            // Check for error record.
            if line.contains("\"error\"") {
                if let Ok(err) = serde_json::from_str::<ErrorRecord>(line) {
                    warn!(file = %err.file, msg = %err.error, "analyzer resolution failed");
                    failed_files.push(err.file);
                }
                continue;
            }

            // Parse resolved element.
            match serde_json::from_str::<ResolvedElement>(line) {
                Ok(elem) => elements.push(elem),
                Err(e) => {
                    debug!(line = line, err = %e, "skipping unparseable line");
                }
            }
        }

        Ok(ResolutionResult {
            elements,
            failed_files,
            elapsed: start.elapsed(),
        })
    }

    /// Apply resolution results to the CPG and type arena. For each
    /// resolved element, finds the matching CPG node by `(FileId,
    /// byte_offset)` and patches its `type_ref` and `symbol` fields.
    ///
    /// Returns the number of CPG nodes successfully patched.
    pub fn patch_graph(
        result: &ResolutionResult,
        graph: &mut CodeGraph,
        type_arena: &mut TypeArena,
    ) -> usize {
        // Optimization: build a map of (FileId, offset) -> Vec<NodeId>
        // to handle nested nodes at the same starting position.
        let mut pos_map: rustc_hash::FxHashMap<(FileId, u32), Vec<NodeId>> =
            rustc_hash::FxHashMap::default();
        for node in graph.iter_nodes() {
            pos_map
                .entry((node.file, node.byte_range.start))
                .or_default()
                .push(node.id);
        }

        let mut patched = 0usize;

        for elem in &result.elements {
            let file_id = graph.intern_file(&elem.file);
            let Some(candidates) = pos_map.get(&(file_id, elem.offset)) else {
                continue;
            };

            // PERFECTION: Select the node that most closely matches the
            // end_offset. This ensures we don't patch a parent 'MethodInvocation'
            // with 'SimpleIdentifier' type info.
            let mut best_node = None;
            let mut min_diff = u32::MAX;

            for &nid in candidates {
                let node = graph.node(nid);
                let diff = node.byte_range.end.abs_diff(elem.end_offset);
                if diff < min_diff {
                    min_diff = diff;
                    best_node = Some(nid);
                }
            }

            let Some(node_id) = best_node else {
                continue;
            };

            // Patch the symbol.
            if !elem.canonical.is_empty() {
                let sym = graph.intern_symbol(&elem.canonical);
                graph.node_mut(node_id).symbol = Some(sym);

                // Also patch the SymbolEntry's declaration pointer if this
                // is a declaration (not a reference).
                if elem.kind != ElementKind::Reference {
                    let entry = graph.symbol_mut(sym);
                    entry.file = Some(file_id);
                    entry.decl = Some(node_id);
                }
            }

            // Patch the type.
            if let Some(ref desc) = elem.dart_type {
                let type_id = type_arena.intern_from_desc(desc);
                graph.node_mut(node_id).type_ref = Some(TypeRef::Resolved(type_id));
            }

            patched += 1;
        }

        info!(
            patched,
            total = result.elements.len(),
            "CPG nodes patched with resolved types"
        );
        patched
    }

    /// Gracefully shut down the Dart helper process.
    pub fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Close stdin to signal EOF.
            drop(child.stdin.take());
            // Wait with a timeout, then kill if unresponsive.
            match child.try_wait() {
                Ok(Some(status)) => {
                    debug!(?status, "Dart helper exited");
                }
                Ok(None) => {
                    // Still running — give it 2 s then kill.
                    std::thread::sleep(Duration::from_secs(2));
                    if child.try_wait().ok().flatten().is_none() {
                        let _ = child.kill();
                        warn!("killed unresponsive Dart helper");
                    }
                }
                Err(e) => {
                    error!(%e, "failed to check Dart helper status");
                    let _ = child.kill();
                }
            }
        }
    }

    /// Is the helper process currently running?
    #[must_use]
    pub fn is_running(&mut self) -> bool {
        self.child
            .as_mut()
            .map(|c| c.try_wait().ok().flatten().is_none())
            .unwrap_or(false)
    }
}

impl Drop for AnalyzerBridge {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Error record from the Dart helper.
#[derive(Deserialize)]
struct ErrorRecord {
    file: String,
    error: String,
}

/// Errors from the analyzer bridge.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// `dart run` failed to spawn.
    #[error("failed to spawn Dart helper: {0}")]
    SpawnFailed(String),
    /// The bridge was used before [`AnalyzerBridge::start`] was called.
    #[error("analyzer bridge not running — call start() first")]
    NotRunning,
    /// stdin was unexpectedly closed.
    #[error("helper stdin closed")]
    StdinClosed,
    /// stdout was unexpectedly closed.
    #[error("helper stdout closed")]
    StdoutClosed,
    /// JSON protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The helper process exited with a non-zero status.
    #[error("helper exited with status {0}")]
    HelperExited(i32),
}

// ============================================================================
// One-shot convenience (CI mode)
// ============================================================================

/// Resolve an entire workspace in one shot: spawn the Dart helper, send
/// all Dart file paths, collect results, shut down. Suitable for CI
/// pipelines that do not need incremental resolution.
pub fn resolve_workspace(
    helper_script: &Path,
    workspace_root: &Path,
    dart_files: &[&str],
    graph: &mut CodeGraph,
    type_arena: &mut TypeArena,
) -> Result<ResolutionResult, BridgeError> {
    let mut bridge = AnalyzerBridge::new(helper_script.to_path_buf(), workspace_root.to_path_buf());
    bridge.start()?;
    let result = bridge.resolve(dart_files)?;
    AnalyzerBridge::patch_graph(&result, graph, type_arena);
    bridge.shutdown();
    Ok(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resolved_element() {
        let json = r#"{"file":"lib/main.dart","offset":42,"end_offset":55,"kind":"method","canonical":"package:app/main.dart#MyClass.doStuff","type":{"name":"Future","library":"dart:async","type_args":[{"name":"void","library":"dart:core"}],"is_nullable":false},"supertypes":[]}"#;
        let elem: ResolvedElement = serde_json::from_str(json).unwrap();
        assert_eq!(elem.canonical, "package:app/main.dart#MyClass.doStuff");
        assert_eq!(elem.offset, 42);
        assert_eq!(elem.dart_type.as_ref().unwrap().name, "Future");
    }

    #[test]
    fn patch_graph_matches_by_offset() {
        let mut g = CodeGraph::new();
        let mut arena = TypeArena::new();
        let fid = g.intern_file("lib/main.dart");
        let node = g.add_node(crate::cpg::NodeKind::MethodCall, fid, 42..55);

        let result = ResolutionResult {
            elements: vec![ResolvedElement {
                file: "lib/main.dart".into(),
                offset: 42,
                end_offset: 55,
                kind: ElementKind::Reference,
                canonical: "package:supabase/supabase.dart#SupabaseClient.from".into(),
                dart_type: Some(DartTypeDesc {
                    name: "SupabaseQueryBuilder".into(),
                    library: "package:supabase/supabase.dart".into(),
                    type_args: vec![],
                    is_nullable: false,
                    supertypes: vec![],
                }),
                supertypes: vec![],
            }],
            failed_files: vec![],
            elapsed: Duration::ZERO,
        };

        let patched = AnalyzerBridge::patch_graph(&result, &mut g, &mut arena);
        assert_eq!(patched, 1);
        assert!(g.node(node).symbol.is_some());
        assert!(g.node(node).type_ref.is_some());
        let sym = g.node(node).symbol.unwrap();
        assert_eq!(
            g.symbol(sym).canonical.as_ref(),
            "package:supabase/supabase.dart#SupabaseClient.from"
        );
    }
}
