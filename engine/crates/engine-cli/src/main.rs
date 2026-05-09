//! engine-cli: command-line driver for the SAST engine.
//!
//! Walks a project, parses every supported source file (Dart, Rust,
//! TypeScript/TSX, SQL), builds the CPG, builds the RDG (Reactive
//! Dependency Graph), loads a Semgrep YAML rule, runs the IFDS solver,
//! and emits findings to stdout as either pretty-printed console text,
//! JSON, or SARIF 2.1.0.
//!
//! The CLI is invoked as a sidecar by both the VS Code extension
//! (`vscode-extension/src/scanner/rustEngine.ts`) and the Dart `lib/`
//! scanner (`lib/src/scanner.dart`). Communication is one-shot: parent
//! invokes the binary, binary prints findings, exits.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use rustc_hash::FxHashMap;
use serde::Serialize;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use engine_core::cpg::reactive_builder::build_rdg;
use engine_core::cpg::{CodeGraph, FileId, NodeId};
use engine_core::frontend::types::TypeArena;
use engine_core::rules::semgrep_compiler::load_rule;
use engine_core::solver::ifds::IfdsSolver;
use engine_core::supabase::populator::{
    extract_dart_clients, extract_edge_functions, extract_rls_policies,
};
use engine_core::supabase::smt::{CorrelationQuery, SupabaseCorrelator, DEFAULT_BUDGET};
use engine_frontend_dart::parse_dart;
use engine_frontend_rust::parse_rust;
use engine_frontend_typescript::{parse_tsx, parse_typescript};
// SQL frontend is consumed by the SMT correlator, not per-file CPG integration.

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Flutter security scanner — Rust analysis kernel"
)]
struct Args {
    /// Path to the project to scan.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Path to a Semgrep YAML rule file.
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Output format: console | json | sarif.
    #[arg(short, long, default_value = "console")]
    format: String,

    /// Dump every CPG node (id, kind, file:byte-range, symbol) to stderr
    /// after construction. Used when debugging why a Semgrep rule fails to
    /// match — surfaces the actual node layout that the pattern compiler
    /// is reasoning over.
    #[arg(long)]
    dump_cpg: bool,

    /// Run the Supabase SMT correlator after the IFDS pass. Cross-references
    /// Dart client calls, optional edge-function wrappers, and the RLS
    /// policies parsed from supabase/migrations/*.sql.
    #[arg(long)]
    enable_smt: bool,

    /// Allow cross-file taint flows in IFDS output. By default only
    /// intra-file flows are reported to reduce noise; enabling this
    /// lets the solver report flows that cross compilation-unit
    /// boundaries via inter-procedural summary edges.
    #[arg(long)]
    cross_file: bool,
}

fn main() -> Result<()> {
    // Send tracing output to stderr so stdout stays clean for the
    // JSON / SARIF payload that parents (TS extension, Dart scanner)
    // parse. Default subscribers go to stdout, which contaminates the
    // adapter's JSON.parse path.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "engine_cli=info,engine_core=info".into()),
        )
        .init();
    let args = Args::parse();

    info!(path = %args.path.display(), "starting scan");

    let mut graph = CodeGraph::new();
    let mut source_map: FxHashMap<FileId, String> = FxHashMap::default();
    let type_arena = TypeArena::new();

    // 1. Ingest files and build the per-file AST/CFG/PDG sub-graphs.
    for entry in WalkDir::new(&args.path)
        .into_iter()
        .filter_entry(should_scan_entry)
        .filter_map(Result::ok)
        .filter(|e| {
            let ext = e.path().extension().and_then(|s| s.to_str());
            matches!(
                ext,
                Some("dart") | Some("rs") | Some("ts") | Some("tsx") | Some("sql")
            )
        })
    {
        let source = std::fs::read_to_string(entry.path())
            .with_context(|| format!("read {}", entry.path().display()))?;
        let file_id = graph.intern_file(
            entry
                .path()
                .to_str()
                .context("non-UTF-8 file path; engine-cli requires UTF-8 paths")?,
        );
        source_map.insert(file_id, source.clone());

        let ext = entry.path().extension().and_then(|s| s.to_str());
        let res = match ext {
            Some("dart") => parse_dart(&mut graph, file_id, &source),
            Some("rs") => parse_rust(&mut graph, file_id, &source),
            Some("ts") => parse_typescript(&mut graph, file_id, &source),
            Some("tsx") => parse_tsx(&mut graph, file_id, &source),
            Some("sql") => {
                // SQL files are consumed by the SMT correlator directly from
                // the filesystem (see extract_rls_policies). No CPG nodes needed.
                Ok(())
            }
            _ => unreachable!("WalkDir filter guarantees one of these extensions"),
        };
        if let Err(e) = res {
            warn!(file = %entry.path().display(), error = %e, "parse failed; file skipped");
        }
    }

    // 2. Build the Reactive Dependency Graph (Flutter widget rebuild edges,
    //    stream subscriptions, Riverpod/Bloc/Provider patterns).
    info!("building reactive dependency graph");
    build_rdg(&mut graph, &type_arena);

    info!(
        nodes = graph.node_count(),
        edges = graph.edge_count(),
        "CPG construction complete",
    );

    if args.dump_cpg {
        eprintln!("--- CPG nodes ---");
        for node in graph.iter_nodes() {
            let symbol = node
                .symbol
                .map(|s| graph.symbol(s).canonical.to_string())
                .unwrap_or_default();
            eprintln!(
                "  #{} {:?} {}:{}..{} symbol={:?}",
                node.id.raw(),
                node.kind,
                graph.file_path(node.file),
                node.byte_range.start,
                node.byte_range.end,
                symbol,
            );
        }
        eprintln!("--- AST edges ---");
        for edge in graph.iter_edges() {
            if let engine_core::cpg::EdgeKind::Ast(a) = edge.kind {
                eprintln!("  #{} -> #{}  Ast({:?})", edge.src.raw(), edge.dst.raw(), a,);
            }
        }
        eprintln!("--- CFG edges ---");
        for edge in graph.iter_edges() {
            if let engine_core::cpg::EdgeKind::Cfg(c) = edge.kind {
                eprintln!("  #{} -> #{}  Cfg({:?})", edge.src.raw(), edge.dst.raw(), c,);
            }
        }
    }

    // 3. Load and run the rule. Skip cleanly when no --rules was given —
    //    the SMT correlator below may still run on its own. Returning
    //    early here would bypass --enable-smt invocations that don't
    //    pair a Semgrep rule with the SMT pass.
    let mut findings: Vec<Finding> = Vec::new();
    let source_refs: FxHashMap<FileId, &str> =
        source_map.iter().map(|(k, v)| (*k, v.as_str())).collect();

    if let Some(rule_path) = args.rules.clone() {
        info!(rule = %rule_path.display(), "loading rule");
        let rule_yaml = std::fs::read_to_string(&rule_path)
            .with_context(|| format!("read rule {}", rule_path.display()))?;

        let flow_funcs = load_rule(&rule_yaml, &graph, &type_arena, &source_refs)
            .map_err(|e| anyhow::anyhow!("rule compile: {e}"))?;

        info!("running IFDS solver");
        let mut solver = IfdsSolver::new(&graph, flow_funcs);

        // Seed the solver at every source the rule discovered.
        let source_ids: Vec<NodeId> = solver.flow().source_node_ids().collect();
        for src in &source_ids {
            solver.seed_at_source(*src);
        }
        solver.run();

        let rule_id = solver.flow().rule().id.clone();
        let rule_msg = solver.flow().rule().message.clone();
        let rule_sev = solver.flow().rule().severity.clone();
        let sink_ids: Vec<NodeId> = solver.flow().sink_node_ids().collect();

        for sink_node in sink_ids {
            if !solver.is_tainted(sink_node) {
                continue;
            }
            let sink = graph.node(sink_node);
            // By default only report intra-file flows to reduce noise.
            // When --cross-file is passed, allow flows that cross
            // compilation-unit boundaries via inter-procedural summary edges.
            if !args.cross_file {
                let source_in_same_file = source_ids.iter().any(|src_id| {
                    let src = graph.node(*src_id);
                    src.file == sink.file
                });
                if !source_in_same_file {
                    continue;
                }
            }
            let file_path = graph.file_path(sink.file).to_owned();
            let (line, col) = byte_to_line_col(
                source_map.get(&sink.file).map(String::as_str).unwrap_or(""),
                sink.byte_range.start as usize,
            );
            findings.push(Finding {
                file: file_path,
                line,
                col,
                rule_id: rule_id.clone(),
                severity: rule_sev.clone(),
                message: rule_msg.clone(),
            });
        }
    } else if !args.enable_smt {
        info!("no --rules and no --enable-smt; nothing to do");
        emit(&args.format, &[])?;
        return Ok(());
    } else {
        info!("no --rules provided; running --enable-smt only");
    }

    // 4. Run the Supabase SMT correlator if --enable-smt was passed.
    //    Reuses the source_refs map already built above.
    if args.enable_smt {
        let smt_findings = run_smt_correlator(&mut graph, &args.path, &source_refs)?;
        findings.extend(smt_findings);
    }

    // 6. Emit.
    emit(&args.format, &findings)?;

    Ok(())
}

fn should_scan_entry(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }

    let Some(name) = entry.file_name().to_str() else {
        return true;
    };

    !matches!(
        name,
        ".dart_tool"
            | ".git"
            | ".idea"
            | ".vscode"
            | "build"
            | "coverage"
            | "dist"
            | "node_modules"
            | "Pods"
            | "target"
    )
}

/// Run the SMT correlator: extract Dart client models from the CPG, parse
/// RLS policies from `supabase/migrations/*.sql`, and correlate each
/// client-policy pair.
fn run_smt_correlator(
    graph: &mut CodeGraph,
    project_root: &Path,
    source_map: &FxHashMap<FileId, &str>,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let correlator = SupabaseCorrelator::new();

    // --- Extract Dart clients from the CPG. ---
    let clients = extract_dart_clients(graph, source_map);
    if clients.is_empty() {
        info!("SMT correlator: no Supabase Dart clients found");
        return Ok(findings);
    }
    info!(
        count = clients.len(),
        "SMT correlator: Dart clients extracted"
    );

    // --- Extract Edge Function models from the CPG (TypeScript files). ---
    let edge_fns = extract_edge_functions(graph);
    info!(
        count = edge_fns.len(),
        "SMT correlator: edge function models extracted"
    );

    // --- Parse RLS policies from supabase/migrations/*.sql ---
    let migrations_dir = project_root.join("supabase").join("migrations");
    let mut sql_buf = String::new();
    if migrations_dir.exists() {
        for entry in walkdir::WalkDir::new(&migrations_dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sql"))
        {
            let content = std::fs::read_to_string(entry.path())
                .with_context(|| format!("read {}", entry.path().display()))?;
            sql_buf.push_str(&content);
            sql_buf.push('\n');
        }
    }

    if sql_buf.is_empty() {
        info!(
            "SMT correlator: no SQL migration files found at {:?}",
            migrations_dir
        );
        // For each client with no policies, flag missing-rls.
        for client in &clients {
            let table_name = graph.symbol(client.table).canonical.to_string();
            info!(
                "SMT correlator: client accesses table '{}' with no RLS policies found",
                table_name
            );
            let (file, line, col) = node_location(graph, source_map, client.call_site);
            findings.push(Finding {
                file,
                line,
                col,
                rule_id: "dart.supabase.missing-rls".to_string(),
                severity: "ERROR".to_string(),
                message: format!(
                    "Table '{}' is accessed via Supabase client but no RLS policy was found. \
                     Without RLS, all rows are accessible to any authenticated user. \
                     Add CREATE POLICY statements in supabase/migrations/.",
                    table_name,
                ),
            });
        }
        return Ok(findings);
    }

    let policies = extract_rls_policies(graph, &sql_buf);
    info!(
        count = policies.len(),
        "SMT correlator: RLS policies parsed"
    );

    // --- Correlate: for each client, find matching policies by table name. ---
    for client in &clients {
        let client_table_name = graph.symbol(client.table).canonical.to_lowercase();

        // Find policies that match this client's table + operation.
        let matching_policies: Vec<&engine_core::supabase::smt::RlsPolicyModel> = policies
            .iter()
            .filter(|p| {
                let p_table = graph.symbol(p.table).canonical.to_lowercase();
                p_table == client_table_name && client.operation.covered_by(p.operation)
            })
            .collect();

        if matching_policies.is_empty() {
            // No policy covers this operation on this table → missing-rls
            let (file, line, col) = node_location(graph, source_map, client.call_site);
            findings.push(Finding {
                file,
                line,
                col,
                rule_id: "dart.supabase.missing-rls".to_string(),
                severity: "ERROR".to_string(),
                message: format!(
                    "Table '{}' has no RLS policy covering {:?} operation. \
                     Without RLS, all rows are accessible to any authenticated user. \
                     Add CREATE POLICY statements in supabase/migrations/.",
                    client_table_name, client.operation,
                ),
            });
            continue;
        }

        // Correlate against each matching policy.
        for policy in matching_policies {
            // Use the client's actual call-site for finding attribution
            // (file path, line, column) rather than a synthetic node.
            let (p_file, p_line, p_col) = node_location(graph, source_map, client.call_site);

            // Find the edge function (if any) for this client's table.
            let matching_edge_fn = edge_fns.iter().find(|ef| {
                // Edge function matches if its name appears in the query context.
                // In practice the edge_fn matches by the source file proximity
                // to the Dart client's supabase directory structure.
                if let Some(ref inner) = ef.inner_query {
                    graph.symbol(inner.table).canonical == graph.symbol(client.table).canonical
                } else {
                    false
                }
            });

            let query = CorrelationQuery {
                client: client.clone(),
                edge_fn: matching_edge_fn.cloned(),
                policy: policy.clone(),
                call_site: client.call_site,
            };

            match correlator.correlate(&query, DEFAULT_BUDGET) {
                Ok(verdict) => match verdict {
                    engine_core::supabase::smt::Verdict::Unsafe { witness } => {
                        findings.push(Finding {
                            file: p_file.clone(),
                            line: p_line,
                            col: p_col,
                            rule_id: "dart.supabase.rls-bypass".to_string(),
                            severity: "ERROR".to_string(),
                            message: format!(
                                "RLS bypass detected for table '{}': {}",
                                client_table_name, witness.model_dump,
                            ),
                        });
                    }
                    engine_core::supabase::smt::Verdict::Unknown { reason, .. } => {
                        // UnsupportedTheory means Z3 is not compiled in — this is
                        // expected in default builds, not a finding-worthy event.
                        // Only emit a WARNING for real uncertainty (Z3 timeout or
                        // opaque predicate).
                        if reason == engine_core::supabase::smt::FallbackReason::UnsupportedTheory {
                            debug!(
                                "SMT correlator: Z3 not available for table '{}' (policy '{}')",
                                client_table_name,
                                graph.symbol(policy.name).canonical,
                            );
                            continue;
                        }
                        warn!(
                            "SMT correlator: Unknown verdict for table '{}': {:?}",
                            client_table_name, reason,
                        );
                        findings.push(Finding {
                            file: p_file.clone(),
                            line: p_line,
                            col: p_col,
                            rule_id: "dart.supabase.rls-uncertain".to_string(),
                            severity: "WARNING".to_string(),
                            message: format!(
                                "RLS correlation uncertain for table '{}' (reason: {:?}). \
                                 Manual review recommended.",
                                client_table_name, reason,
                            ),
                        });
                    }
                    engine_core::supabase::smt::Verdict::Safe { .. } => {
                        info!("SMT correlator: Safe for table '{}'", client_table_name,);
                    }
                },
                Err(e) => {
                    warn!(
                        "SMT correlator: correlation error for table '{}': {:?}",
                        client_table_name, e,
                    );
                }
            }
        }
    }

    Ok(findings)
}

#[derive(Serialize, Debug)]
struct Finding {
    file: String,
    line: u32,
    col: u32,
    rule_id: String,
    severity: String,
    message: String,
}

fn emit(format: &str, findings: &[Finding]) -> Result<()> {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(findings)?),
        "sarif" => println!("{}", to_sarif(findings)?),
        _ => {
            if findings.is_empty() {
                println!("no findings");
            } else {
                for f in findings {
                    println!(
                        "{}:{}:{}: [{}] {} ({})",
                        f.file, f.line, f.col, f.severity, f.message, f.rule_id,
                    );
                }
            }
        }
    }
    Ok(())
}

/// Convert a UTF-8 byte offset into a 1-based (line, column) pair.
fn byte_to_line_col(source: &str, byte_offset: usize) -> (u32, u32) {
    let mut line = 1u32;
    let mut col = 1u32;
    for (i, ch) in source.char_indices() {
        if i >= byte_offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Resolve the file path, line, and column for a CPG node.
///
/// Uses `source_map` to recover the source text for the node's file, then
/// computes the 1-based line/col from the node's byte range.
fn node_location(
    graph: &CodeGraph,
    source_map: &FxHashMap<FileId, &str>,
    node: NodeId,
) -> (String, u32, u32) {
    let n = graph.node(node);
    let file_path = graph.file_path(n.file).to_owned();
    let (line, col) = source_map
        .get(&n.file)
        .map(|src| byte_to_line_col(src, n.byte_range.start as usize))
        .unwrap_or((0, 0));
    (file_path, line, col)
}

/// Minimal SARIF 2.1.0 envelope.
fn to_sarif(findings: &[Finding]) -> Result<String> {
    let runs = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "engine-cli",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/dilpreet-s-sidhu/flutter-security-scanner",
                }
            },
            "results": findings.iter().map(|f| serde_json::json!({
                "ruleId": f.rule_id,
                "level": severity_to_sarif_level(&f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": &f.file },
                        "region": { "startLine": f.line, "startColumn": f.col }
                    }
                }]
            })).collect::<Vec<_>>()
        }]
    });
    Ok(serde_json::to_string_pretty(&runs)?)
}

fn severity_to_sarif_level(s: &str) -> &'static str {
    match s.to_uppercase().as_str() {
        "ERROR" | "CRITICAL" | "HIGH" => "error",
        "WARNING" | "MEDIUM" => "warning",
        _ => "note",
    }
}
