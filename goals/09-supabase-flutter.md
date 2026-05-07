# 09 — Preserve and extend the Supabase / Flutter / Dart edge

This is where we already lead CodeQL — they don't ship Dart, and they
don't have specific Supabase / Flutter rules. The work here is to
**stay** ahead and extend the lead so that the niche becomes
unbeatable. Even if every other goal in this folder slipped, finishing
this file alone keeps us best-in-class for Flutter/Supabase teams.

---

## Status (as of 2026-05-07)

Legend: ✅ DONE | 🟡 PARTIAL | ⏳ REMAINING (default).

- ✅ §SF-2, §SF-3, §SF-4, §SF-6, §SF-9, §SF-10, §SF-11, §SF-12, §SF-13,
  §SF-24, §SF-25
- 🟡 §SF-1 (verify_jwt + CORS + service-role-in-response landed; dedicated
  `Deno.env.get`/`kv.set`/`console.log(secrets)` rules still pending),
  §SF-7 (rich source set landed; deeper `Navigator.pushNamed` sink modeling
  still pending), §SF-13 (WebView extended in d412b65 + d0af6b4 added the
  Android `addJavascriptInterface` rule)
- ⏳ §SF-5, §SF-8, §SF-14–§SF-23, §SF-26–§SF-30

---

## §SF-1 — Supabase Edge Functions (Deno) coverage 🟡 PARTIAL — sha b00eb5d

- **Why:** Edge Functions ship security risks specific to the Deno
  runtime (env access, fetch with attacker URLs, KV stores).
- **Current state:** Some coverage exists per the
  `supabase-edge-function-secrets` rule history.
- **Target state:** Dedicated rules for:
  - `Deno.env.get(name)` returning secrets to client (CWE-200)
  - `Deno.serve(handler)` route handler taint sources
  - `kv.set(key, taint)` followed by `kv.get(key)` flowing to HTML
  - `console.log(secrets)` in Deno.serve
- **Approach:** New rules under `vscode-extension/src/rules/supabase/edge*`.
- **Dependencies:** None.
- **Effort:** **M** (~1 week).

## §SF-2 — Supabase Realtime subscription scope ✅ DONE — sha d0af6b4 (2026-05-07)

- **Why:** Unscoped Realtime subscriptions leak data to all clients.
- **Current state:** Per commit history, partial rule exists.
- **Target state:** Detect `.channel('public:posts')` without a
  `.eq('user_id', userId)` filter; flag CWE-639.
- **Effort:** **M** (3 days).
- **Implementation notes:**
  - Added `unscoped-realtime-channel` for Dart and JS/TS Supabase clients.
  - Flags `schema:table` realtime channel subscriptions that lack an ownership
    filter in the surrounding chain.
  - Recognizes `.eq(...)`, Supabase `filter: "user_id=eq..."`, and Dart
    `PostgresChangeFilter(column: ...)` style scoping.

## §SF-3 — Supabase RPC injection ✅ DONE — sha 79e5ef6

- **Why:** Dynamic RPC names + user-controlled args = privilege
  escalation.
- **Current state:** Partial rule per commit history.
- **Target state:** Detect `supabase.rpc(taint, args)` and
  `supabase.rpc('foo', { col: taint })` where the function name is
  attacker-controlled.
- **Effort:** **M** (3 days).

## §SF-4 — Supabase signed-URL TTL ✅ DONE — sha fb84ff1

- **Current state:** ✅ rule exists per commit history.
- **Target state:** Maintenance only.

## §SF-5 — Supabase RLS policy *generation* from DDL

- **Why:** Today we can suggest RLS policies; we can't read existing
  policies and verify they cover the access patterns we observe.
- **Current state:** `rls-policy-suggestion` rule emits suggestions.
- **Target state:** Parse SQL migrations / `supabase/migrations/*.sql`
  files. Build a model of `CREATE POLICY` statements per table. Cross-
  reference with detected `.from('table')` accesses. Flag tables with
  access patterns not covered by policies.
- **Approach:**
  1. Use existing tree-sitter SQL grammar (or a small Postgres dialect
     parser).
  2. Build `Map<table, Policy[]>` from DDL.
  3. For each `tableAccess` in `ProjectContext`, evaluate whether the
     observed access is covered.
- **Dependencies:** None.
- **Effort:** **L** (~2 weeks).
- **Tests:** Fixture: a Supabase project with `posts` table, RLS
  enabled, INSERT policy covering ownership but SELECT policy missing.
  Expected finding: SELECT not covered.

## §SF-6 — Supabase `service_role` key client-side leak ✅ DONE — sha ca7785a + 8868ef1 (JWT decode)

- **Current state:** ✅ rule exists per commit history (`supabase-service-role-key-in-client`).
- **Target state:** Maintenance + a related rule: `service_role` JWT
  payload decode (`jwt.decode` reveals the role; per
  `generic-secret`'s JWT decoding work).
- **Effort:** **S** maintenance.

## §SF-7 — Flutter deep-link sources (extend existing rule) 🟡 PARTIAL — sha 0ca0d71

- **Why:** `getInitialLink()`, `linkStream`, `app.getIntent()`,
  `MethodChannel('app/route').invokeMethod` all bring user data.
- **Current state:** `deep-link-validation` rule on Dart side.
- **Target state:** Extended source set; deeper sink modeling
  (especially `Navigator.pushNamed(deepLinkPath)`).
- **Effort:** **M** (4 days).

## §SF-8 — Flutter `MethodChannel` argument taint

- **Why:** Native bridges receive arbitrary Dart data; on the platform
  side it's user input.
- **Current state:** Not modeled.
- **Target state:** Track `MethodChannel.invokeMethod(name, args)`
  where `args` is tainted. Flag for native-side review.
- **Approach:** Sink kind `native-channel`. Since we can't analyze
  the iOS/Android side, this is a "review-required" finding.
- **Effort:** **M** (3 days).

## §SF-9 — Flutter biometric auth misuse ✅ DONE — sha 1631d80

- **Current state:** ✅ rule exists per commit history (`biometric-auth`).
- **Target state:** Maintenance + extend to cover `local_auth`'s
  `authenticate(stickyAuth: false)` pattern (CWE-287).
- **Effort:** **S** (1 day).

## §SF-10 — Flutter release-hardening checks ✅ DONE — sha 1acead9

- **Current state:** ✅ rule exists per commit history (`release-hardening`).
- **Target state:** Maintenance + extend:
  - `kReleaseMode` checks for debug code paths
  - debug-keystore detection in Android build
  - allowBackup=true in AndroidManifest.xml
- **Effort:** **M** (3 days).

## §SF-11 — Flutter platform-security plist / manifest ✅ DONE — sha df332b2

- **Current state:** ✅ rule exists per commit history (`platform-security`).
- **Target state:** Maintenance + extend:
  - iOS: `NSAllowsArbitraryLoads` true → CWE-319
  - Android: cleartextTrafficPermitted in `network-security-config.xml`
- **Effort:** **S** (1 day).

## §SF-12 — Insecure-storage on sqflite + Hive ✅ DONE — sha d0af6b4 (2026-05-07)

- **Current state:** ✅ extended per commit history.
- **Target state:** Extend to `flutter_secure_storage` misuse (e.g.
  using it then logging the value).
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added `secure-storage-logging`.
  - Tracks sensitive values read from `flutter_secure_storage` and flags
    `print` / `debugPrint` / `developer.log` of those values.

## §SF-13 — WebView security deep checks ✅ DONE — sha d0af6b4 (2026-05-07)

- **Current state:** ✅ extended per commit history.
- **Target state:** Specific rules for:
  - `setJavaScriptEnabled(true)` + tainted `loadUrl`
  - `evaluateJavascript(taint)`
  - `addJavaScriptInterface` exposing native methods
- **Effort:** **M** (3 days).
- **Implementation notes:**
  - Existing Dart CLI WebView checks cover unrestricted JavaScript,
    user-controlled `loadUrl`, `javascript:` loads, and dynamic
    `evaluateJavascript` / `runJavaScript`.
  - Added VS Code extension rule `android-webview-js-interface` for Java/Kotlin
    `addJavascriptInterface(...)` bridge exposure.

## §SF-14 — Dart IFDS: extend source patterns

- **Already covered:** [01-language-coverage.md §LC-14](01-language-coverage.md).

## §SF-15 — Dart IFDS: virtual dispatch

- **Already covered:** [01-language-coverage.md §LC-15](01-language-coverage.md).

## §SF-16 — Dart IFDS: cascade operator handling

- **Why:** Dart cascade `..method()` is common. Today the IFDS
  builder may not model it correctly.
- **Current state:** Documented as a limitation in README.
- **Target state:** Cascade chains preserve receiver taint through
  every link.
- **Approach:** AST walk of `cascade` nodes; treat each invocation as
  a method call with the receiver, propagating taint normally.
- **Effort:** **M** (3 days).

## §SF-17 — Dart IFDS: named arguments

- **Why:** `func(name: tainted, value: clean)` — taint must be carried
  to the parameter named `name`.
- **Current state:** Documented limitation.
- **Target state:** Parameter-by-name resolution in the IFDS builder.
- **Approach:** Walk `argument` nodes for `:` syntax. Resolve to
  parameter index by name.
- **Effort:** **M** (3 days).

## §SF-18 — Dart IFDS: field-sensitive class members

- **Why:** Documented limitation. `obj.field = taint` then `sink(obj.field)`
  doesn't propagate.
- **Current state:** Limitation.
- **Target state:** Field-sensitive `Loc` representation in the IFDS
  graph.
- **Effort:** **L** (~2 weeks).

## §SF-19 — Dart IFDS: collection-sensitive

- **Why:** `list.add(taint); for (var x in list) sink(x)` should
  propagate.
- **Current state:** Limitation.
- **Target state:** Treat collections as a single fact carrying the
  meet of all element taints.
- **Effort:** **L** (~2 weeks).

## §SF-20 — Flutter / Supabase project template

- **Why:** Lower friction for new users — give them a `flutter create`
  + `supabase init` template that's pre-configured with our scanner.
- **Current state:** None.
- **Target state:** A `flutter-supabase-helper init` command that adds
  `.fshrc.yaml`, `.github/workflows/sast.yml`, and a `pre-commit`
  config to a Flutter/Supabase project.
- **Effort:** **M** (1 week).

## §SF-21 — Documentation: best-practices guide

- **Why:** Capture the security model behind RLS, signed URLs, and
  edge-function isolation. Each section linked from a relevant rule.
- **Current state:** Brief mentions in rule `fix` text.
- **Target state:** A separate `docs/supabase-security.md` that
  every Supabase rule's `fix` text links to.
- **Effort:** **M** (1 week).

## §SF-22 — Auto-generate RLS policies from access patterns

- **Why:** A killer feature. Today we suggest one-off policies. CodeQL
  can't do this — it's Supabase-specific.
- **Current state:** `rls-policy-suggestion` emits suggestions per
  table.
- **Target state:** Aggregate detected access patterns across the whole
  scan and emit a complete `migration.sql` that grants the right
  policies. Available as `flutter-supabase-helper generate-rls .`.
- **Approach:** From `tableAccesses`, derive (table, operation,
  ownership-column) tuples. Emit `CREATE POLICY` per tuple.
- **Effort:** **L** (~2 weeks).
- **Tests:** Fixture: project with multiple tables and access
  patterns; assert generated SQL matches a reference.

## §SF-23 — Supabase migration safety review

- **Why:** Migrations that drop columns, drop tables, alter constraints
  in production are high-risk. SAST can flag these.
- **Current state:** None.
- **Target state:** New rule `supabase-migration-risk` reviewing files
  in `supabase/migrations/` for drop-column / drop-table / break-FK
  patterns.
- **Effort:** **M** (3 days).

## §SF-24 — Supabase Storage public-bucket detection (already shipped)

- **Current state:** ✅ `public-storage` rule.
- **Target state:** Maintenance.

## §SF-25 — Real-time client subscription resource leak ✅ DONE — sha d0af6b4 (2026-05-07)

- **Why:** Forgotten `subscription.unsubscribe()` leaks Realtime
  channels.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added `realtime-subscription-leak`.
  - Flags assigned realtime subscriptions/channels with no same-file
    `unsubscribe()` / `removeChannel(...)` cleanup.

## §SF-26 — Supabase Auth flow misconfig

- **Target state:** Detect missing email-verification, weak password
  policy, missing MFA, refresh-token reuse patterns.
- **Effort:** **L** (~2 weeks).

## §SF-27 — Flutter form validation gaps

- **Target state:** `TextFormField` without `validator`; submit
  pressed without form.validate().
- **Effort:** **M** (3 days).

## §SF-28 — Flutter PII disclosure via logger packages

- **Why:** Common to use `logger` package; common to log entire
  request/response bodies.
- **Effort:** **M** (3 days).

## §SF-29 — Flutter / Dart SDK vulnerability check

- **Target state:** Read `pubspec.lock`. Cross-reference with the OSS
  Vulnerability Database (OSV) entries for Dart packages. Emit
  findings for vulnerable versions.
- **Effort:** **L** (~2 weeks).

## §SF-30 — Cross-platform build artifact security

- **Target state:** Detect `.aab` / `.ipa` build configs that disable
  obfuscation, expose `assets/`.
- **Effort:** **M** (3 days).
