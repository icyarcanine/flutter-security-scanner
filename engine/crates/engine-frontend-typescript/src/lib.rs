//! TypeScript Frontend for the SAST Engine.
//!
//! Parses `.ts` and `.tsx` files using tree-sitter-typescript and
//! lowers them into the CPG with AST and CFG sub-graphs. This is
//! essential for analyzing Supabase Edge Functions written in TypeScript
//! and detecting service-role key leaks.

pub mod ast_builder;
pub mod cfg_builder;

use engine_core::cpg::{CodeGraph, FileId};
use tree_sitter::{Language, Parser};

/// Orchestrates parsing and 2-pass lowering of a `.ts` file into the CPG.
pub fn parse_typescript(
    graph: &mut CodeGraph,
    file_id: FileId,
    source: &str,
) -> Result<(), String> {
    let mut parser = Parser::new();
    let language: Language = tree_sitter_typescript::language_typescript();
    parser.set_language(&language).map_err(|e| e.to_string())?;

    let tree = parser
        .parse(source, None)
        .ok_or("Failed to parse TypeScript source")?;

    // Pass 1: Build AST skeleton
    let mut ast_builder = ast_builder::AstBuilder::new(graph, file_id, source);
    ast_builder.build(&tree);

    // Pass 2: Build CFG pulse
    let mut cfg_builder = cfg_builder::CfgBuilder::new(graph);
    cfg_builder.build(tree.root_node());

    Ok(())
}

/// Orchestrates parsing and 2-pass lowering of a `.tsx` file into the CPG.
pub fn parse_tsx(graph: &mut CodeGraph, file_id: FileId, source: &str) -> Result<(), String> {
    let mut parser = Parser::new();
    let language: Language = tree_sitter_typescript::language_tsx();
    parser.set_language(&language).map_err(|e| e.to_string())?;

    let tree = parser
        .parse(source, None)
        .ok_or("Failed to parse TypeScript source")?;

    // Pass 1: Build AST skeleton
    let mut ast_builder = ast_builder::AstBuilder::new(graph, file_id, source);
    ast_builder.build(&tree);

    // Pass 2: Build CFG pulse
    let mut cfg_builder = cfg_builder::CfgBuilder::new(graph);
    cfg_builder.build(tree.root_node());

    Ok(())
}
