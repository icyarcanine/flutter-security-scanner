# 11 — Quick wins (< 1 day each)

Read this file first. Each task in here is **less than a day** of work
and closes a real gap. Twenty of these together cover more of the
benchmark gap than any single hard task in [00-engine.md](00-engine.md).

If you have a few hours, pick from here. If your scope is multi-day,
read the deeper files.

---

## §QW-1 — Sink-specific sanitizer applicability ([04-precision.md §PR-6](04-precision.md))

- **Effort:** **S** (1 day post §PR-5).
- **Direct fix to a benchmark FN/FP.** Document `sanitizesFor`
  per sink kind in the sanitizer registry. Easy now.

## §QW-2 — `instanceof T` narrows receiver type ([00-engine.md §EN-12](00-engine.md))

- **Effort:** **S** (1 day post §EN-4).
- Once §EN-4 lands, this is one method.

## §QW-3 — Dynamic `import(taint)` flag ([03-rule-coverage.md §RC-50](03-rule-coverage.md))

- **Effort:** **S** (1 day).
- Add to the existing sink kind `code`. Single test fixture.

## §QW-4 — Hardcoded IP literal flag ([03-rule-coverage.md §RC-58](03-rule-coverage.md))

- **Effort:** **S** (1 day).
- Plain regex over source. New rule.

## §QW-5 — `rejectUnauthorized: false` flag ([03-rule-coverage.md §RC-43](03-rule-coverage.md))

- **Effort:** **S** (1 day).
- Detect via regex.

## §QW-6 — `target="_blank"` without `rel` (tabnabbing) ([03-rule-coverage.md §RC-13](03-rule-coverage.md))

- **Effort:** **S** (1 day).

## §QW-7 — Plain `http://` in production HTTP clients ([03-rule-coverage.md §RC-19](03-rule-coverage.md))

- **Effort:** **S** (1 day).

## §QW-8 — Weak crypto on JS side ([03-rule-coverage.md §RC-20](03-rule-coverage.md))

- **Effort:** **S** (1 day).
- Mirror the Dart-side `weak-crypto` rule.

## §QW-9 — Stripe/Twilio/SendGrid/OpenAI/Anthropic token shapes ([03-rule-coverage.md §RC-21](03-rule-coverage.md))

- **Effort:** **S** (1 day per provider).
- Each is one regex addition to `genericSecretRule`.

## §QW-10 — Header injection (CRLF) ([03-rule-coverage.md §RC-4](03-rule-coverage.md))

- **Effort:** **S** (1 day).

## §QW-11 — `crypto.randomBytes` with small `n` ([04-precision.md §PR-18](04-precision.md))

- **Effort:** **S** (1 day).
- Add `Number`, `+`, `~~`, `| 0`, `>>> 0` as numeric coercion.

## §QW-12 — Engine: bounded rule runtime ([05-scale.md §SC-8](05-scale.md))

- **Effort:** **S** (1 day).
- One `Promise.race`. Catches catastrophic regex hangs.

## §QW-13 — Bounded file size with logged warning ([05-scale.md §SC-4](05-scale.md))

- **Effort:** **S** (1 day).
- Today silent skip; add a warning + count in scan output.

## §QW-14 — Markdown report output ([06-integrations.md §IN-10](06-integrations.md))

- **Effort:** **S** (1 day).
- Mirror the SARIF emitter; output a Markdown table.

## §QW-15 — CSV export ([06-integrations.md §IN-11](06-integrations.md))

- **Effort:** **S** (1 day).

## §QW-16 — JUnit XML output ([06-integrations.md §IN-8](06-integrations.md))

- **Effort:** **S** (1 day).

## §QW-17 — `--format=gitlab` Code Quality output ([06-integrations.md §IN-4](06-integrations.md))

- **Effort:** **S** (1 day).

## §QW-18 — `--format=bitbucket` Code Insights output ([06-integrations.md §IN-6](06-integrations.md))

- **Effort:** **S** (1 day).

## §QW-19 — `--diff-against=<sarif>` mode ([06-integrations.md §IN-27](06-integrations.md))

- **Effort:** **S** (2 days, but the second day is tests).

## §QW-20 — Confidence-based fail flag (`--fail-confidence`) ([06-integrations.md §IN-28](06-integrations.md))

- **Effort:** **S** (1 day).

## §QW-21 — Config schema for `.fshrc.yaml` ([06-integrations.md §IN-30](06-integrations.md))

- **Effort:** **S** (1 day).
- Publish a JSON schema; VS Code pickup is automatic.

## §QW-22 — Suppression-comment count surfacing ([04-precision.md §PR-15](04-precision.md))

- **Effort:** **S** (1 day).
- Helps users notice noisy rules.

## §QW-23 — JWT algorithm confusion (RS256→HS256 with public key) ([03-rule-coverage.md §RC-60](03-rule-coverage.md))

- **Effort:** **M** (3 days).
- New jwt-misuse pattern. CVE-2018-0114 class.

## §QW-24 — `process.env.SECRET` written to log ([03-rule-coverage.md §RC-3](03-rule-coverage.md))

- **Effort:** **S** (1 day).
- Already partial via `sensitive-logging`; extend the patterns.

## §QW-25 — `eval(`taint`)` regex prefilter exit-fast ([05-scale.md §SC-3](05-scale.md))

- **Effort:** **S** (1 day).
- Today every file is checked. Add a `.includes('eval(')` short-circuit before AST parse.

## §QW-26 — JSON Schema for config files ([06-integrations.md §IN-30](06-integrations.md))

- **Effort:** **S** (1 day).

## §QW-27 — Path traversal: `path.join(__dirname, taint)` flag ([03-rule-coverage.md §RC-24](03-rule-coverage.md))

- **Effort:** **S** (1 day).

## §QW-28 — Symlink-following sink ([03-rule-coverage.md §RC-25](03-rule-coverage.md))

- **Effort:** **S** (2 days).

## §QW-29 — TLSv1 / SSL3 deprecated protocols ([03-rule-coverage.md §RC-48](03-rule-coverage.md)) ✅ DONE — sha f2d31ad (2026-05-07)

- **Effort:** **S** (1 day).

## §QW-30 — Stored credentials in `localStorage` / `sessionStorage` ([03-rule-coverage.md §RC-55](03-rule-coverage.md)) ✅ DONE — sha f2d31ad (2026-05-07)

- **Effort:** **S** (1 day).

## §QW-31 — Cookie domain too-broad warning ([03-rule-coverage.md §RC-45](03-rule-coverage.md)) ✅ DONE — sha f2d31ad (2026-05-07)

- **Effort:** **S** (1 day).

## §QW-32 — `crypto.createCipher` insecure-mode ([03-rule-coverage.md §RC-44](03-rule-coverage.md)) ✅ DONE — sha f2d31ad (2026-05-07)

- **Effort:** **S** (1 day).

## §QW-33 — Unscoped Realtime channel ([09-supabase-flutter.md §SF-2](09-supabase-flutter.md))

- **Effort:** **M** (3 days).
- Already partial.

## §QW-34 — Forgotten `subscription.unsubscribe()` ([09-supabase-flutter.md §SF-25](09-supabase-flutter.md))

- **Effort:** **S** (1 day).

## §QW-35 — `flutter_secure_storage` then logging ([09-supabase-flutter.md §SF-12](09-supabase-flutter.md))

- **Effort:** **S** (1 day).

## §QW-36 — `addJavaScriptInterface` exposing native ([09-supabase-flutter.md §SF-13](09-supabase-flutter.md))

- **Effort:** **S** (1 day).

## §QW-37 — Auto-detect typosquats in `package.json` ([03-rule-coverage.md §RC-35](03-rule-coverage.md))

- **Effort:** **S** (1 day).
- Static list.

## §QW-38 — `String.prototype.replace` with sanitizer regex recognition ([00-engine.md §EN-14](00-engine.md))

- **Effort:** **S** (1 day, builds on §EN-14).

## §QW-39 — `JSON.parse(taint)` propagation ([00-engine.md §EN-14](00-engine.md))

- **Effort:** **S** (1 day, part of §EN-14).

## §QW-40 — `URLSearchParams.get(literal)` always tainted ([00-engine.md §EN-14](00-engine.md))

- **Effort:** **S** (1 day, part of §EN-14).

## §QW-41 — Negate-guard recognition (`if (!allow.has(x)) return;`) ([04-precision.md §PR-1](04-precision.md))

- **Effort:** **S** (1 day post §EN-4).
- A simple inversion of §PR-1's logic.

## §QW-42 — Telemetry for scan duration distribution ([05-scale.md §SC-16](05-scale.md))

- **Effort:** **S** (1 day).

## §QW-43 — Information-via-exception (`res.send(err.stack)`) ([03-rule-coverage.md §RC-18](03-rule-coverage.md)) ✅ DONE — sha f2d31ad (2026-05-07)

- **Effort:** **S** (1 day).

## §QW-44 — Format-string injection (Python `'%s' % taint`) ([03-rule-coverage.md §RC-27](03-rule-coverage.md))

- **Effort:** **S** (1 day).

## §QW-45 — `setTimeout(taint)` (string-form code execution) — already handled, verify ([00-engine.md](00-engine.md))

- **Effort:** **S** (audit only).

## §QW-46 — Clipboard exposure on JS side ([03-rule-coverage.md §RC-56](03-rule-coverage.md)) ✅ DONE — sha f2d31ad (2026-05-07)

- **Effort:** **S** (1 day).

## §QW-47 — `--format=html` standalone HTML report ([06-integrations.md §IN-9](06-integrations.md))

- **Effort:** **M** (4 days). Bigger; included because the value is high.

## §QW-48 — `pre-commit-config.yaml` snippet in README ([06-integrations.md §IN-22](06-integrations.md))

- **Effort:** **S** (1 day, mostly docs).

## §QW-49 — `.github/workflows/sast.yml` example ([06-integrations.md §IN-24](06-integrations.md))

- **Effort:** **S** (1 day, mostly docs).

## §QW-50 — Slack notification ([06-integrations.md §IN-19](06-integrations.md))

- **Effort:** **S** (1 day).

---

## Order suggested

If you're a single agent working through this in priority order:

1. §QW-12 (bounded runtime) — protects every other change.
2. §QW-13 (bounded file size with warning) — surfaces silently-skipped files.
3. §QW-1 (sink-specific sanitizers) — closes a precision gap.
4. §QW-21 (config schema) — improves user UX immediately.
5. §QW-3, 4, 5, 6, 7, 8, 9, 10 — eight new rules in eight days.
6. §QW-14, 15, 16, 17, 18 — five new output formats in five days.
7. §QW-22 (suppression abuse warning) — feedback loop.
8. The rest, in any order based on what's blocked / unblocked.

Tracking: as you finish a task, mark it `✅ DONE — sha <commit>` in
this file. Don't delete entries.
