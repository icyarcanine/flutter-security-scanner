//! Modular Rust Frontend for the SAST Engine.

pub mod ast_builder;
pub mod cfg_builder;

use engine_core::cpg::{CodeGraph, FileId};
use tree_sitter::{Language, Parser};

/// Orchestrates the parsing and lowering of a Rust file into the CPG.
pub fn parse_rust(graph: &mut CodeGraph, file_id: FileId, source: &str) -> Result<(), String> {
    let mut parser = Parser::new();
    let language: Language = tree_sitter_rust::language();
    parser.set_language(&language).map_err(|e| e.to_string())?;

    let tree = parser
        .parse(source, None)
        .ok_or("Failed to parse Rust source")?;

    // Pass 1: Build AST skeleton.
    let mut ast_builder = ast_builder::AstBuilder::new(graph, file_id);
    ast_builder.build(&tree);
    let mapping = ast_builder.mapping();

    // Pass 2: Build CFG pulse.
    let mut cfg_builder = cfg_builder::CfgBuilder::new(graph, mapping);
    cfg_builder.build(tree.root_node());

    // Note: Rust-specific desugaring, ICFG, and PDG passes would follow here.
    // For now, we reuse the universal logic where possible.

    Ok(())
}
