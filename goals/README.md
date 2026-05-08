# goals/ — SAST roadmap

This folder is the project roadmap for improving the scanner. It exists so
that a contributor or agent can pick up one file and work on it without
loading the entire repo history.

## Honest framing

Do not use these docs to claim CodeQL parity or superiority. CodeQL is a
mature whole-program analysis system; this project is a lightweight hybrid
scanner with useful Flutter/Supabase/Dart coverage and a growing JS/TS rule
set. Comparative claims need a reproducible benchmark that is not currently
checked into this repo.

There are two viable strategies:

1. **Head-to-head match** — close every gap in [§00–§07](.). Years of work.
2. **Differentiation** — focus on surfaces mainstream SAST tools do not
   model deeply: zero-config setup, Flutter/Dart, Supabase/edge platforms,
   useful autofixes, real-time IDE feedback, and incremental rescans.

The files in this folder list **everything** for both strategies. Agents
working on the project should pick a file based on the strategy currently
chosen, not pick at random.

## File index

| File | Scope | Strategy this serves |
|------|-------|----------------------|
| [00-engine.md](00-engine.md) | Taint engine fundamentals — cross-file, async, points-to, CFG, type narrowing | Head-to-head |
| [01-language-coverage.md](01-language-coverage.md) | Per-language source/sink depth (JS, TS, Python, Java, Go, C/C++, C#, Ruby, Swift, Kotlin, Dart) | Both |
| [02-framework-models.md](02-framework-models.md) | Express, NestJS, Next.js, Django, Spring, Rails, ASP.NET, ORMs, etc. | Both |
| [03-rule-coverage.md](03-rule-coverage.md) | Missing or partial vulnerability classes (prototype pollution, ReDoS depth, log injection, XXE, …) | Head-to-head |
| [04-precision.md](04-precision.md) | Guard reasoning, sanitizer evidence, barrier nodes, confidence calibration | Both |
| [05-scale.md](05-scale.md) | Whole-program DB, incremental rescan, monorepo support, memory bounds | Head-to-head |
| [06-integrations.md](06-integrations.md) | SARIF features, GitHub PR comments, GitLab, IDE plugins, dashboards | Differentiation |
| [07-rule-authoring.md](07-rule-authoring.md) | Custom rule DSL (Semgrep/QL alternative), rule sharing, plugin architecture | Differentiation |
| [08-quality-evals.md](08-quality-evals.md) | OWASP Benchmark, Juliet (NIST), SARD, real-CVE corpus, ML-ranking, telemetry | Both |
| [09-supabase-flutter.md](09-supabase-flutter.md) | Preserve and extend Supabase/Flutter/Dart-specific checks | Differentiation |
| [10-non-goals.md](10-non-goals.md) | What we deliberately won't pursue and why | Both |
| [11-quick-wins.md](11-quick-wins.md) | Completed small-task backlog; append new sub-day tasks here when discovered | Both |

## How to read each file

Every task entry in every file uses this exact shape:

```
### Task name (a stable anchor like §SQ-1)

- **Why:** one sentence stating the user-visible benefit
- **Current state:** path-cited evidence of what we have today
- **Target state:** what "done" looks like, observable from CLI / API
- **Approach:** the actual implementation strategy. Specific functions,
  data structures, edge cases. Not vague.
- **Dependencies:** other §-numbered tasks that must land first
- **Effort:** S (< 1 day) / M (1–5 days) / L (1–4 weeks) / XL (months)
- **Tests:** what fixture(s) prove the task is done
- **Risks / non-obvious gotchas:** the things that bite during implementation
```

If a task is missing one of those fields, treat that as a bug in the goals
doc — open a fix.

## Effort ratings, calibrated

| Rating | Wall time for one engineer / agent | Examples |
|---|---|---|
| **S** | < 1 day | Add a regex sink to an existing rule. Promote a heuristic to a setting. Fix a documented FP. |
| **M** | 1–5 days | New rule end-to-end with tests. Add framework source-set. Wire a new output format. |
| **L** | 1–4 weeks | New language at AST + sink-set level. Refactor the taint engine to support a new analysis dimension (e.g. async). New benchmark suite. |
| **XL** | > 1 month | New language with full taint. Whole-program DB layer. Custom rule DSL with parser + runtime. Distributed scan workers. |

Estimates assume someone who already knows the codebase and the technique.
For an LLM agent or new contributor, multiply by 2–3×.

## How to pick a task

1. Check [11-quick-wins.md](11-quick-wins.md) first. As of May 2026 its
   listed quick wins are marked complete, so new work usually belongs in
   the parent goals files.
2. If you have multi-week scope: pick something from §00 (engine) or §05
   (scale). These unblock everything else.
3. If you're rule-authoring: pick from §03 first, then §02 (framework
   models help every rule downstream).
4. If you're doing UX / integrations: §06 and §08.
5. **Do not** start a §00 task and a §05 task in the same PR. Both
   touch core infrastructure and merging them will hurt.

## Convention: how each goals file numbers tasks

`§<area>-<index>` where `<area>` is two letters (`EN`, `LC`, `FM`, `RC`,
`PR`, `SC`, `IN`, `RA`, `QE`, `SF`, `QW`) and `<index>` is sequential
within that file.

Anchors stay stable. **Never renumber** — agents will have those numbers
in their context. Append new tasks with the next index, even if it leaves
ordering imperfect.

## Status conventions

When a task lands, mark it in-place:

```
### Task name (§EN-1) ✅ DONE — sha 0f434cf
```

Use 🟡 PARTIAL for landed-but-incomplete:

```
### Task name (§EN-1) 🟡 PARTIAL — sha 0f434cf — <what's still missing>
```

Use ⏳ REMAINING when explicitly noting unstarted work (default; a
heading without any marker is also implicitly remaining).

Keep the marker line; do not delete the entry. The history is the
artifact.

Each goals file (00–09, 11) starts with a "Status (as of <date>)" block
listing which §-anchors are DONE / PARTIAL / REMAINING. That block is
the canonical at-a-glance summary; inline markers on individual headings
are the detail. As of 2026-05-07, the blocks reflect the post-merge
state of `feat/production-pass-2026-05`.

## Compare to where we are today (May 2026)

Use the checked-in test suites for verified project state:

- `npm test` in `vscode-extension/`
- `HOME=/tmp dart run tool/smoke_test.dart`
- `dart test`
- `dart analyze lib bin tool test`

There is no current, reproducible CodeQL-vs-this-tool benchmark checked in.
Any future comparison should live under a real benchmark harness with fixture
inputs, scanner outputs, CodeQL outputs, and scoring code.
