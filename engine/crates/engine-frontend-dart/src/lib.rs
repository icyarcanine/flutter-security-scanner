//! Modular Dart Frontend for the SAST Engine.

pub mod ast_builder;
pub mod cfg_builder;
pub mod desugar;
pub mod icfg_builder;
pub mod pdg_builder;

use engine_core::cpg::{CodeGraph, FileId};
use tree_sitter::{Language, Parser};

/// Orchestrates the parsing and 5-pass lowering of a Dart file into the CPG.
pub fn parse_dart(graph: &mut CodeGraph, file_id: FileId, source: &str) -> Result<(), String> {
    let mut parser = Parser::new();
    let language: Language = tree_sitter_dart::language();
    parser.set_language(&language).map_err(|e| e.to_string())?;

    let tree = parser
        .parse(source, None)
        .ok_or("Failed to parse Dart source")?;

    // Pass 1: Build AST skeleton (1:1 CST mapping).
    let mut ast_builder = ast_builder::AstBuilder::new(graph, file_id);
    ast_builder.build(&tree);
    let mapping = ast_builder.mapping();

    // Pass 2: Build CFG pulse (intra-procedural flow).
    let mut cfg_builder = cfg_builder::CfgBuilder::new(graph, mapping);
    cfg_builder.build(tree.root_node());

    // Pass 3: Desugar (normalize cascades, implicit this, etc).
    let mut desugar = desugar::DesugarPass::new(graph);
    desugar.run();

    // Pass 4: Build ICFG (cross-function call/return links).
    let mut icfg_builder = icfg_builder::IcfgBuilder::new(graph);
    icfg_builder.build();

    // Pass 5: Build PDG (reaching definitions / data dependence).
    let mut pdg_builder = pdg_builder::PdgBuilder::new(graph);
    pdg_builder.build();

    Ok(())
}
