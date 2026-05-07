# 10 — Non-goals

What we will deliberately **not** chase, with the reason. Listed so
agents don't reinvent justifications for skipping them.

The principle: be honest about where we can't compete, and use the
saved effort on things where we can.

---

## §NG-1 — C / C++ memory safety analysis

- **Why skipped:** CodeQL's C/C++ pack is the product of 15+ years of
  Semmle work plus ongoing GitHub Security Lab investment. Memory
  safety analysis (use-after-free, buffer overflow, integer overflow,
  null deref, format strings) requires:
  - Pointer aliasing analysis
  - Heap modeling
  - Lifetime analysis
  - Complex CFG modeling for goto / setjmp / longjmp
  - Per-architecture undefined-behavior modeling
  Each of these is a multi-month engineering effort. We cannot match
  CodeQL on this.
- **Alternative:** Document that users with C/C++ codebases should run
  CodeQL alongside our scanner. Don't pretend we're a replacement.
- **Reconsider when:** Never. C/C++ memory safety is the wrong battle.

## §NG-2 — Building our own QL-equivalent query language

- **Why skipped:** QL took Semmle a decade and a research budget.
  Designing a Datalog-equivalent and a sound implementation is
  research-grade work.
- **Alternative:** Adopt YAML rules (Semgrep-style) — see
  [07-rule-authoring.md §RA-1](07-rule-authoring.md). 80% of the
  expressiveness, 5% of the engineering.
- **Reconsider when:** Never. The market validates YAML; we should
  follow.

## §NG-3 — Distributed cloud-hosted scan service

- **Why skipped:** GitHub Code Scanning + CodeQL Cloud is a hosted
  service. Building our own SaaS on top of the engine is a separate
  product (auth, billing, multi-tenancy, infra). Off-strategy for an
  open-source CLI / extension.
- **Alternative:** Be excellent at on-prem / self-hosted /
  self-served via the GitHub Action. Let users host their own
  dashboard ([06-integrations.md §IN-26](06-integrations.md)).
- **Reconsider when:** A clear funded path to commercial SaaS exists
  AND we have product-market fit on the OSS side.

## §NG-4 — Custom AST grammar engine (replacing tree-sitter)

- **Why skipped:** tree-sitter is a great fit. Per-language grammar
  authoring beyond what tree-sitter ships is a years-long project.
- **Alternative:** Use tree-sitter for everything. When a grammar is
  missing or buggy, contribute upstream.

## §NG-5 — IDE plugins beyond VS Code, IntelliJ, Vim

- **Why skipped:** Limited engineering bandwidth. Sublime / Atom /
  Emacs all have small audiences relative to the Big Three.
- **Alternative:** Document how the CLI integrates with `flycheck`,
  `LSP-mode`, and similar.
- **Reconsider when:** A community contributor proposes a port; accept
  but don't drive.

## §NG-6 — Compliance reporting (PCI / SOC2 / HIPAA)

- **Why skipped:** Compliance reporting requires per-control mappings
  + auditor relationships + ongoing certification effort. It's
  enterprise-product territory.
- **Alternative:** Map findings to CWE (already done) and let
  compliance tooling consume our SARIF.

## §NG-7 — Binary / bytecode analysis

- **Why skipped:** Source-only is our scope. Binary analysis (JVM
  bytecode, .NET MSIL, native binaries) is a different toolchain
  entirely.
- **Alternative:** Stay source-side.

## §NG-8 — Dependency / vulnerability scanning (full SCA)

- **Why skipped:** SCA (npm audit, Snyk, Dependabot) is a different
  product class. Doing it well requires a vulnerability database,
  package-version resolution, and reachability analysis.
- **Alternative:** Generate CycloneDX SBOMs
  ([06-integrations.md §IN-12](06-integrations.md)) and let users plug
  into Snyk / OSV.dev / npm audit.
- **Reconsider when:** Never. Different tool category.

## §NG-9 — Container / IaC scanning

- **Why skipped:** Trivy, Checkov, kics, tfsec already do this well.
  Different domain.
- **Alternative:** Document chaining: run trivy on Dockerfiles, run
  us on the source.

## §NG-10 — Runtime / DAST integration

- **Why skipped:** DAST is a different methodology entirely (running
  app + simulated attacks). Not in scope for SAST.
- **Alternative:** Stay SAST-focused.

## §NG-11 — Deep ML model for vulnerability detection

- **Why skipped:** SAST primarily benefits from precise rules + good
  taint analysis. Hand-crafted rules are more debuggable than
  black-box ML. ML for finding **ranking** is okay
  ([08-quality-evals.md §QE-12](08-quality-evals.md)); ML for finding
  **detection** is not.
- **Alternative:** Use ML for ranking / explanation only.

## §NG-12 — Symbolic execution / constraint solving (Z3-style)

- **Why skipped:** Z3 / KLEE-style symbolic execution is a research
  area. It scales poorly and explodes on realistic inputs. The
  precision benefit isn't worth the complexity for the kinds of
  bugs we're chasing.
- **Alternative:** Symbolic execution lite for constants
  ([04-precision.md §PR-16](04-precision.md)) is enough.

## §NG-13 — Closed-source / proprietary licensing

- **Why skipped:** The differentiation strategy depends on
  community contribution. A closed-source license blocks both.
- **Alternative:** Stay MIT.

## §NG-14 — Centralized rule package marketplace (commercial)

- **Why skipped:** A free marketplace via npm
  ([07-rule-authoring.md §RA-6](07-rule-authoring.md)) is enough.
  Commercial marketplace requires payment infra.

## §NG-15 — A specific rule for every CVE published

- **Why skipped:** CVE-driven rule authorship doesn't scale. Better
  to detect the *class* of bug.
- **Alternative:** Use the CVE corpus
  ([08-quality-evals.md §QE-4](08-quality-evals.md)) as a
  benchmark, not as a rule generator.

## §NG-16 — Auto-PR creation for fixes

- **Why skipped:** Auto-PRs are noise unless the fix is genuinely
  safe and the codebase has reviewers. Risk of automated bad fixes
  outweighs convenience.
- **Alternative:** Quick fixes in the IDE
  ([06-integrations.md §IN-14](06-integrations.md)). User decides.

## §NG-17 — IPv6 / network-protocol-specific bugs

- **Why skipped:** Out of scope for application-level SAST.

## §NG-18 — Rust support beyond what tree-sitter-rust provides

- **Why skipped:** Rust's borrow checker already prevents the bugs
  SAST normally catches. Limited value for the engineering cost.
- **Alternative:** Skip Rust. Users with Rust codebases use clippy +
  cargo-audit.

## §NG-19 — Mobile app store policy compliance

- **Why skipped:** App-store policies change quarterly. Tooling
  ages out fast.

## §NG-20 — Detection of generic obfuscation / packer

- **Why skipped:** False-positive heaven. Legitimate minified code
  trips every heuristic.

---

## When to revisit non-goals

These are not permanent. Reconsider when:

1. The strategy changes (e.g. commercial SaaS direction).
2. A community contributor brings substantial implementation.
3. The cost calculus changes (tree-sitter ships a perfect Rust
   grammar with built-in semantics, etc.).

If reconsidered, **move the entry from this file to the relevant
goals file**, with the reasoning history preserved as a comment.
