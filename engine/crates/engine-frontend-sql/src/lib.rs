//! SQL Frontend for the SAST Engine.
//!
//! Parses SQL policy statements (DDL) into AST models for the SMT correlator.
//! Unlike the regex-based `extract_rls_policies` in `populator.rs`, this
//! frontend builds a proper AST so that complex policy expressions with
//! nested subqueries, compound AND/OR predicates, and `auth.uid()` references
//! are accurately represented.

pub mod model;
pub mod parser;

pub use model::*;
pub use parser::*;

/// Parse SQL policy DDL statements from source text.
pub fn parse_sql_policies(source: &str) -> Vec<RlsPolicyAst> {
    let parser = parser::SqlParser::new(source);
    parser.parse_all()
}
