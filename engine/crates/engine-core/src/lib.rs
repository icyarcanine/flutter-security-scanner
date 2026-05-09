//! engine-core: the analysis kernel of flutter-security-scanner.
//!
//! This crate contains the four pillars of the total-dominance architecture:
//!
//! 1. [`cpg`]      — the unified Code Property Graph
//!                   (AST ∪ CFG ∪ ICFG ∪ PDG ∪ SDG ∪ RDG)
//! 2. [`solver`]   — the IFDS/IDE reachability solver over the
//!                   exploded supergraph (Reps–Horwitz–Sagiv, POPL'95)
//! 3. [`supabase`] — the Z3-backed three-way correlator
//!                   (Dart client ↔ TS edge function ↔ Postgres RLS)
//!
//! Subsequent crates under `engine/crates/` will add:
//!
//! - `engine-semgrep`  — YAML ingestion that lifts Semgrep rules onto our
//!                       inter-procedural SDG+IFDS engine for a 10× precision
//!                       boost over vanilla Semgrep on day one;
//! - `engine-pointer`  — Andersen-style, field-sensitive pointer analysis
//!                       encoded in pure-Rust `crepe`/`datafrog` Datalog;
//! - `engine-frontends`— tree-sitter-based Dart, TypeScript, and Postgres
//!                       frontends that materialise the CPG.
//!
//! The crate is split so that the whole kernel (CPG + IFDS + correlator)
//! compiles to a single `cdylib` that the VS Code extension loads via
//! `wasm-bindgen`, giving the editor sub-100 ms feedback from the same code
//! that CI runs in CI.

#![warn(missing_docs)]
#![allow(
    clippy::module_name_repetitions,
    clippy::too_many_lines,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

pub mod cpg {
    //! Code Property Graph — see [`graph`].
    pub mod graph;
    #[cfg(feature = "persist")]
    pub mod persistence;
    pub mod reactive_builder;
    pub use graph::*;
}

pub mod solver {
    //! Inter-procedural data-flow solver — see [`ifds`].
    pub mod ifds;
    pub use ifds::*;
}

pub mod frontend {
    //! Language frontends that populate the CPG.
    //!
    //! `dart_analyzer` shells out to a Dart process via `std::process` and
    //! is therefore native-only — gated behind the `analyzer-bridge`
    //! feature so WASM builds can opt out.
    #[cfg(feature = "analyzer-bridge")]
    pub mod dart_analyzer;
    pub mod types;
}

pub mod rules {
    //! Rule compilers — Semgrep YAML → IFDS flow functions.
    pub mod semgrep_compiler;
}

/// Supabase correlation engine — populator + SMT (see [`smt`]).
pub mod supabase {
    pub mod populator;
    pub mod smt;
    pub use populator::*;
    pub use smt::*;
}
