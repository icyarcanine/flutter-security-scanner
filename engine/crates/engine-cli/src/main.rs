//! engine-cli: command-line driver for the SAST engine.
//!
//! Walks a project, parses every supported source file (Dart, Rust),
//! builds the CPG, builds the RDG (Reactive Dependency Graph), loads a
//! Semgrep YAML rule, runs the IFDS solver, and emits findings to stdout
//! as either pretty-printed console text, JSON, or SARIF 2.1.0.
//!
//! The CLI is invoked as a sidecar by both the VS Code extension
//! (`vscode-extension/src/scanner/rustEngine.ts`, Phase 5) and the Dart
//! `lib/` scanner (`lib/src/scanner.dart`, Phase 7). Communication is
//! one-shot: parent invokes the binary, binary prints findings, exits.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use rustc_hash::FxHashMap;
use serde::Serialize;
use tracing::{info, warn};
use walkdir::WalkDir;

use engine_core::cpg::reactive_builder::build_rdg;
use engine_core::cpg::{CodeGraph, FileId, NodeId};
use engine_core::frontend::types::TypeArena;
use engine_core::rules::semgrep_compiler::load_rule;
use engine_core::solver::ifds::IfdsSolver;
use engine_frontend_dart::parse_dart;
use engine_frontend_rust::parse_rust;

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
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
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
        .filter_map(Result::ok)
        .filter(|e| {
            let ext = e.path().extension().and_then(|s| s.to_str());
            matches!(ext, Some("dart") | Some("rs"))
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
                eprintln!(
                    "  #{} -> #{}  Ast({:?})",
                    edge.src.raw(),
                    edge.dst.raw(),
                    a,
                );
            }
        }
        eprintln!("--- CFG edges ---");
        for edge in graph.iter_edges() {
            if let engine_core::cpg::EdgeKind::Cfg(c) = edge.kind {
                eprintln!(
                    "  #{} -> #{}  Cfg({:?})",
                    edge.src.raw(),
                    edge.dst.raw(),
                    c,
                );
            }
        }
    }

    // 3. Load and run the rule.
    let Some(rule_path) = args.rules.clone() else {
        info!("no --rules provided; engine ran but no analysis performed");
        emit(&args.format, &[])?;
        return Ok(());
    };

    info!(rule = %rule_path.display(), "loading rule");
    let rule_yaml = std::fs::read_to_string(&rule_path)
        .with_context(|| format!("read rule {}", rule_path.display()))?;

    let source_refs: FxHashMap<FileId, &str> =
        source_map.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let flow_funcs = load_rule(&rule_yaml, &graph, &type_arena, &source_refs)
        .map_err(|e| anyhow::anyhow!("rule compile: {e}"))?;

    info!("running IFDS solver");
    let mut solver = IfdsSolver::new(&graph, flow_funcs);

    // Seed the solver at every source the rule discovered.
    let source_ids: Vec<NodeId> = solver.flow().source_node_ids().collect();
    for src in source_ids {
        solver.seed_at_source(src);
    }
    solver.run();

    // 4. Walk every sink the rule discovered; emit a finding when the IFDS
    //    solver reports the sink is reachable from a tainted fact.
    let rule_id = solver.flow().rule().id.clone();
    let rule_msg = solver.flow().rule().message.clone();
    let rule_sev = solver.flow().rule().severity.clone();
    let sink_ids: Vec<NodeId> = solver.flow().sink_node_ids().collect();

    let mut findings: Vec<Finding> = Vec::new();
    for sink_node in sink_ids {
        if !solver.is_tainted(sink_node) {
            continue;
        }
        let node = graph.node(sink_node);
        let file_path = graph.file_path(node.file).to_owned();
        let (line, col) = byte_to_line_col(
            source_map.get(&node.file).map(String::as_str).unwrap_or(""),
            node.byte_range.start as usize,
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

    // 5. Emit.
    emit(&args.format, &findings)?;

    Ok(())
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

/// Minimal SARIF 2.1.0 envelope. The TS extension's
/// `vscode-extension/src/output/sarif.ts` is the canonical, fuller emitter;
/// the engine sidecar produces a simpler shape that the TS side merges via
/// `scanner/mergeReports.ts`.
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
