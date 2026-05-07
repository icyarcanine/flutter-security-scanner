# 03 — Rule coverage

Every CWE class CodeQL ships a query for that we don't yet have. Each
entry is one rule. Most are S–M effort and the gap closure scales linearly.

We currently have 24 rules covering ~10 CWE classes. CodeQL's JS pack
alone ships 250+ queries. This file walks the gap.

For shape and registration steps, mirror existing rules under
[`vscode-extension/src/rules/`](../vscode-extension/src/rules/).

---

## Status (as of 2026-05-07)

Legend: ✅ DONE | 🟡 PARTIAL | ⏳ REMAINING (default).

After the 2026-05-07 quick-win sweep (sha f2d31ad / e330ed4 / d0af6b4),
many §RC tasks landed via the §QW-* anchors that pointed back to them.
See [GOALS_PROGRESS.md](../GOALS_PROGRESS.md) for the canonical mapping.

- ✅ §RC-4 (CRLF header injection — §QW-10), §RC-13 (tabnabbing — §QW-6),
  §RC-18 (error info disclosure — §QW-43), §RC-19 (cleartext HTTP — §QW-7),
  §RC-20 (weak crypto JS — §QW-8), §RC-21 (vendor token shapes — §QW-9),
  §RC-24 (JS path traversal — §QW-27), §RC-25 (symlink-following — §QW-28),
  §RC-27 (Python format-string — §QW-44), §RC-35 (dependency confusion —
  §QW-37), §RC-43 (rejectUnauthorized — §QW-5), §RC-44 (createCipher —
  §QW-32), §RC-45 (broad cookie domain — §QW-31), §RC-48 (deprecated TLS —
  §QW-29), §RC-50 (dynamic import sink — §QW-3), §RC-55 (web-storage
  credentials — §QW-30), §RC-56 (clipboard exposure JS — §QW-46),
  §RC-58 (hardcoded IP — §QW-4), §RC-60 (JWT alg confusion — §QW-23)
- 🟡 §RC-3 (log injection) — env-secret-logging subcase covered (§QW-24);
  CRLF log-splitting still pending.
- ⏳ §RC-1, §RC-2, §RC-5..§RC-12, §RC-14..§RC-17, §RC-22, §RC-23, §RC-26,
  §RC-28..§RC-34, §RC-36..§RC-42, §RC-46, §RC-47, §RC-49, §RC-51..§RC-54,
  §RC-57, §RC-59, §RC-61, §RC-62 are unstarted.

The "✅ HIGH PRIORITY" markers in this file pre-date the convention and
mean "do this first," NOT "done."

---

## §RC-1 — Prototype pollution (CWE-1321) ⏳ REMAINING (HIGH PRIORITY)

- **Why:** Major Node-ecosystem vulnerability class. Misses fixture 07.
- **Current state:** No rule.
- **Target state:** Detect:
  1. Recursive merge / extend functions writing to `__proto__` /
     `constructor` / `prototype` keys.
  2. `Object.assign(target, attackerSource)` where `target` is shared.
  3. `lodash.set(obj, attackerKey, val)` patterns.
  4. Any `obj[tainted] = anything` write where `obj` is a config /
     options object.
- **Approach:**
  1. New rule `proto-pollution` in `rules/security/protoPollutionRule.ts`.
  2. AST stage. Walk `assignment_expression` where the LHS is a
     computed property write (`obj[expr] = …`) AND `expr` resolves
     (transitively) to a tainted source.
  3. Special-case: detect recursive merge via call to a function whose
     parameter is shadowed and used in a recursive call. Heuristic for
     the common merge() / deepExtend() pattern.
- **Dependencies:** §EN-15 (dynamic property write tracking) gives us
  the underlying mechanism.
- **Effort:** **M** (3 days).
- **Tests:** Re-run COMPARISON.md fixture 07. Add `lodash.set` test;
  Add a Hoek-style merge test.
- **Risks / gotchas:** FP risk on legitimate `obj[knownLiteral] = val`.
  Restrict to tainted keys.

## §RC-2 — ReDoS / catastrophic backtracking (CWE-1333) ⏳ REMAINING (HIGH PRIORITY)

- **Why:** Misses fixture 08. Common in input validators.
- **Current state:** No rule.
- **Target state:** Detect regex literals with nested quantifiers:
  `(a+)+`, `(a*)*`, `(a|a)+`, ambiguous alternations. Flag both
  static literals AND dynamic regexes constructed from user input.
- **Approach:**
  1. New rule `redos`. Stage AST.
  2. Walk `regex` literal nodes. Parse the pattern with a small NFA
     analyser (port `safe-regex2`-style algorithm).
  3. For dynamic regexes (`new RegExp(taint)`), flag as "potentially
     unsafe" at MEDIUM.
- **Dependencies:** None.
- **Effort:** **M** (4 days).
- **Tests:** `(a+)+`, `(a*)*$`, `(a|a)+`, plus negative tests on safe
  regexes. Check our own code with the rule.
- **Risks / gotchas:** Keep the analyser bounded (max 200 states).
  Bail out on very large patterns.

## §RC-3 — Log injection (CRLF in logs) (CWE-117) ✅ MEDIUM PRIORITY

- **Why:** Common, easily exploited for log forgery.
- **Current state:** `sensitive-logging` flags logging of secrets but
  not log injection (writing tainted data through `\n` / `\r` into log
  records).
- **Progress:** §QW-24 landed the `process.env.SECRET` logging subcase
  in `sensitive-logging` at sha `e330ed4` (2026-05-07). The full CRLF log
  injection taint rule remains open.
- **Target state:** New rule `log-injection`. Detect tainted strings
  reaching `console.log/warn/error/info`, Winston `logger.info(taint)`,
  Pino, Bunyan, etc. — without `\r` / `\n` stripping.
- **Approach:** Sink kind `log`. Flag tainted args. Sanitizers:
  any function whose name contains `escape` / `redact` / regex
  containing `\r\n`.
- **Dependencies:** §EN-2 (Promise) for Winston async loggers.
- **Effort:** **S** (1 day).
- **Tests:** `console.log(taint)`, Winston, Pino fixtures.

## §RC-4 — Header injection / response splitting (CWE-113) ✅ DONE — sha f2d31ad (2026-05-07)

- **Why:** Tainted data into `Set-Cookie` / `Location` headers can
  forge new headers via `\r\n`.
- **Current state:** No rule.
- **Target state:** Detect tainted strings reaching `res.setHeader(name, taint)`,
  `res.cookie(name, taint, …)` with `\r\n` not stripped, `res.location(taint)`.
- **Approach:** Sink kind `header`. Sanitizer: `encodeURIComponent`,
  `replace(/\r\n/, '')`.
- **Dependencies:** None.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added `'header'` to `SinkKind` in `taint/dataFlow.ts`; CWE-113 in
    `injectionRule._cweForSink`.
  - Recognised sinks: `res.setHeader`, `res.header`, `res.cookie`,
    `res.location` (re-classed from `redirect` since the CRLF risk is
    more serious), `res.writeHead`, `res.append`.
  - Existing sanitizer registry already includes `encodeURIComponent`,
    so `res.setHeader('X', encodeURIComponent(req.body.x))` is correctly
    treated as safe. `replace(/\r\n/, '')` heuristic deferred — rare.
  - Dynamic-only mode disabled for header sinks (legitimate code sets
    headers from dynamic values constantly); only confirmed taint flow
    flags.
  - Injection rule prefilter regex extended to include the new methods.
  - 4 tests in `scripts/taint-engine.test.js`.

## §RC-5 — Open redirect deepening (CWE-601)

- **Why:** We already detect `res.redirect(taint)`. Real apps build
  redirects via concatenation: `res.redirect('/' + taint)` where
  attacker controls the path.
- **Current state:** Naive sink detection.
- **Target state:** Detect `'/' + taint` redirects, verify allowlist
  guards.
- **Approach:** Already partially handled by taint engine; add a
  barrier guard for `URL`-shaped allowlist checks (depends on §EN-4).
- **Dependencies:** §EN-4.
- **Effort:** **S** (1 day post §EN-4).

## §RC-6 — XML external entity (XXE) (CWE-611)

- **Why:** Common in JS XML parsers (`fast-xml-parser`, `xml2js`,
  `libxmljs`) when configured insecurely.
- **Current state:** No rule.
- **Target state:** Detect `xml2js.parseString(taint)` with
  `explicitRoot: false` etc., `libxmljs.parseXmlString(taint, { noent: true })`,
  and `DOMParser`-based XML in JS.
- **Approach:** Per-library sink registration with config-flag detection.
- **Dependencies:** None.
- **Effort:** **M** (3 days).

## §RC-7 — XPath injection (CWE-643) — already partial

- **Current state:** `xpath.evaluate`, `selectSingleNode`, `selectNodes`
  flagged via `kind: 'sql'`.
- **Target state:** Verify and add `xmldom` xpath.
- **Effort:** **S** (1 day).

## §RC-8 — LDAP injection (CWE-90) — already partial

- **Current state:** `ldap.search`, `*.search_s`, `searchEntries`
  flagged.
- **Target state:** Add `ldapjs` and Active Directory shapes.
- **Effort:** **S** (1 day).

## §RC-9 — Command injection variants (CWE-78)

- **Why:** We detect `exec/spawn`. Newer `execa`, `cross-spawn`,
  `shelljs` not modeled.
- **Current state:** Stdlib only.
- **Target state:** Add `execa.sync(taint)`, `shelljs.exec(taint)`,
  `cross-spawn.sync(taint)`, `child_process.fork(taint)`,
  `shell-quote.parse(taint)`.
- **Effort:** **S** (1 day).

## §RC-10 — Insecure deserialization variants (CWE-502)

- **Why:** Beyond pickle/yaml. JS has `node-serialize`, `funcster`,
  `serialize-javascript`, `worker_threads`'s `parentPort.on('message', …)`
  with raw deserialization.
- **Effort:** **M** (2 days).

## §RC-11 — Server-side request forgery deepening (CWE-918)

- **Why:** We have basic SSRF. Cloud-metadata-service-specific (AWS
  EC2 IMDS, GCP metadata) detection is more nuanced.
- **Target state:** Flag SSRF where the URL points to known cloud
  metadata IPs (`169.254.169.254`, `metadata.google.internal`) in any
  fetch call.
- **Effort:** **S** (1 day).

## §RC-12 — Cross-site script inclusion (XSSI) (CWE-79 family)

- **Why:** Risk when secret data is serialized as JSON via `<script>`
  injection.
- **Effort:** **M** (2 days).

## §RC-13 — Tabnabbing (CWE-1022) ✅ DONE — sha f2d31ad (2026-05-07)

- **Why:** `target="_blank"` without `rel="noopener noreferrer"` lets
  the destination access `window.opener`.
- **Current state:** No rule.
- **Target state:** Detect JSX `<a target="_blank">` without `rel`,
  HTML files, `window.open` without `noopener`.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - New rule `tabnabbing` (RuleStage.fast, CWE-1022, MEDIUM/HIGH-conf).
  - Two patterns: anchor tag `<a target="_blank">` and
    `window.open(url, '_blank', features?)`.
  - Suppressed when `rel` contains `noopener` or `noreferrer`, or when
    the windowFeatures string contains either token.
  - File-type gate: `.html|.htm|.js|.jsx|.ts|.tsx|.mjs|.cjs|.vue|.svelte|.astro`.
  - 4 tests in `scripts/taint-engine.test.js`.

## §RC-14 — Insecure file upload sinks (CWE-434)

- **Why:** Beyond Supabase storage (which we have). Multer / Formidable
  / Busboy / S3 puts.
- **Effort:** **M** (2 days).

## §RC-15 — Race conditions / TOCTOU (CWE-367)

- **Why:** Filesystem `fs.exists()` then `fs.read()`.
- **Current state:** No rule.
- **Target state:** Detect a `fs.access(p)` followed by `fs.readFile(p)`
  in the same function.
- **Effort:** **S** (1 day).

## §RC-16 — Improper authentication (CWE-287)

- **Target state:** Detect missing auth middleware on routes flagged
  with sensitive-method names (`admin`, `delete`, `transfer`).
- **Effort:** **L** (~1 week — semantic-shape detection).

## §RC-17 — Insecure direct object reference (IDOR) (CWE-639)

- **Why:** The classic API auth bug. Ours `client-side-trust` rule
  partially overlaps for Supabase but misses general IDOR.
- **Target state:** Detect `req.params.id` used in `findOne(id)` /
  ORM lookup without an `userId === currentUser.id` check.
- **Effort:** **L** (~1 week).

## §RC-18 — Information exposure through exception (CWE-209) ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** Detect `res.send(err.message)` / `res.send(err.stack)`
  patterns.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - New `error-info-disclosure` rule covers Express/Fastify-style response
    calls and Koa `ctx.body = ...` assignments.
  - `err.stack` and raw error-object responses are HIGH; `err.message` is
    MEDIUM because validation errors can be legitimate when explicitly
    whitelisted.
  - Negative test keeps generic 500 responses quiet.

## §RC-19 — Cleartext transmission of sensitive info (CWE-319) ✅ DONE — sha f2d31ad (2026-05-07)

- **Why:** `http://` instead of `https://` in HTTP clients.
- **Current state:** Partial — we don't have a dedicated rule.
- **Target state:** Flag `fetch('http://...')` patterns where `https://`
  would be expected (production URLs).
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - New rule `cleartext-http` (RuleStage.fast, CWE-319, MEDIUM).
  - Recognised clients: `fetch`, `axios.*`, `got.*`, `ky.*`, `superagent.*`,
    `request`, `https.get/request`, `XMLHttpRequest.open`.
  - Loopback (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`) and RFC 1918
    ranges (10.x, 192.168.x, 172.16-31.x) auto-suppressed — local-dev
    cleartext is not a deployable risk.
  - Skips Dart files; Dart-side `plaintext-http` rule covers those.
  - Uses `stripLineComment` so `//`-comment URLs don't trigger.
  - 4 tests in `scripts/taint-engine.test.js`.

## §RC-20 — Weak cryptography variants (CWE-327) ✅ DONE — sha f2d31ad (2026-05-07)

- **Implementation notes:**
  - New JS-side rule `weak-crypto-js` mirrors the Dart `weak-crypto`.
  - Catches: `crypto.createHash('md5'|'sha1'|...)`,
    `crypto.createHmac('md5'|'sha1', ...)`,
    `crypto.createCipheriv('aes-*-ecb'|'des'|'3des'|'rc4'|'blowfish', ...)`,
    `CryptoJS.MD5/SHA1/MD4/MD2`, `CryptoJS.mode.ECB`,
    `crypto.subtle.digest('SHA-1'|'MD5', ...)`.
  - One finding per line (multi-pattern lines fold to first match) so
    a misuse doesn't produce a stack of overlapping findings.
  - Tests in `scripts/taint-engine.test.js` cover MD5, ECB, CryptoJS,
    and a SHA-256 negative.

- **Why:** We have `weak-crypto` rule on the Dart side. JS side missing.
- **Target state:** Detect `crypto.createCipher('des', …)` /
  `crypto.createHash('md5')` / `crypto.createHash('sha1')` in security
  contexts.
- **Effort:** **S** (1 day).

## §RC-21 — Hardcoded credentials variants (already strong) ✅ DONE — sha f2d31ad (2026-05-07)

- **Implementation notes:**
  - Added 7 vendor-specific regexes to `genericSecretRule` patterns array,
    each gated to a distinctive prefix so confidence stays HIGH:
    - **Stripe** `(sk|rk|pk)_(live|test)_[A-Za-z0-9]{24,}`
    - **Twilio** `(AC|SK)[0-9a-fA-F]{32}` (account / API-key SIDs)
    - **SendGrid** `SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{32,80}`
    - **OpenAI** `sk-(proj-)?[A-Za-z0-9_-]{20,}`
    - **Anthropic** `sk-ant(-api\d+)?-[A-Za-z0-9_-]{40,}`
    - **GitHub** `gh[pousr]_[A-Za-z0-9]{36,255}`
    - **Slack** `xox[baprs]-[A-Za-z0-9-]{10,}`
  - Existing AWS / private-key / JWT patterns kept at LOW confidence to
    avoid breaking the precision-self-test contract.
  - 4 new tests in `scripts/taint-engine.test.js`.

- **Current state:** `hardcoded-secrets`, `generic-secret` cover AWS,
  GCP, JWT, generic.
- **Target state:** Add Stripe, Twilio, SendGrid, OpenAI, Anthropic,
  Slack, GitHub, Azure, Heroku token shapes.
- **Effort:** **S** (1 day per provider; ongoing).

## §RC-22 — Insecure cookie variants (CWE-1004/614/352) — already covered

- **Current state:** ✅ Done. Track maintenance only.

## §RC-23 — Insecure randomness (CWE-338) — already covered

- **Current state:** ✅ Done.

## §RC-24 — Path traversal variants (CWE-22) ✅ DONE — sha e330ed4 (2026-05-07)

- **Current state:** Dart side has `path-traversal` rule. JS side
  doesn't have a dedicated rule but covers it via `injection-flaw`
  with sink kind `path`.
- **Target state:** Dedicated `path-traversal` rule for JS that
  recognizes `path.join(__dirname, taint)` as traversal-prone unless
  guarded.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added JS/TS rule `path-traversal-js`.
  - Flags tainted values flowing into `path.join(...)`,
    `path.resolve(...)`, and matching `node:path` aliases.
  - Keeps safe literal path construction clean and covers common
    `req.query` / `req.params` sources.

## §RC-25 — Symlink following (CWE-59) ✅ DONE — sha d0af6b4 (2026-05-07)

- **Target state:** Flag `fs.readFile(path, options)` where path is
  user-controlled and `options` doesn't include `withFileTypes` /
  symlink-rejection check.
- **Effort:** **M** (2 days).
- **Implementation notes:**
  - Added JS/TS rule `symlink-following`.
  - Flags obvious user-controlled `fs.readFile` / `fs.open` / stream/stat
    paths unless a nearby `realpath` / `lstat` / `O_NOFOLLOW` guard exists.
  - Emits CWE-59 at MEDIUM confidence to keep review context explicit.

## §RC-26 — Type confusion (CWE-843) — JS specific

- **Target state:** `typeof x === 'string'` on values that flow into
  numeric operations.
- **Effort:** **M** (3 days).

## §RC-27 — Format string (CWE-134) — Python's % and f-strings ✅ DONE — sha d0af6b4 (2026-05-07)

- **Target state:** Detect `'admin: %s' % taint` and `f"admin: {taint}"`
  flowing to log/SQL/command sinks.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added `python-format-injection`.
  - Flags direct SQL/command/log sink calls using `%` formatting or f-strings
    with request/input/sys.argv/environment data.
  - Keeps parameterized SQL calls clean.

## §RC-28 — Resource exhaustion (CWE-400)

- **Target state:** Detect unbounded user input in array length,
  string repeat (`taint.repeat(taint)`), recursion depth.
- **Effort:** **L** (~1 week).

## §RC-29 — Privilege escalation through SQL (CWE-269)

- **Target state:** SQL queries that update privilege fields with
  user-controlled data.
- **Effort:** **M** (3 days).

## §RC-30 — Information leak through timing (CWE-208)

- **Target state:** `password === userInput` (string comparison) is
  timing-leaky. Flag, suggest `crypto.timingSafeEqual`.
- **Effort:** **S** (1 day).

## §RC-31 — Stored XSS (CWE-79 stored variant)

- **Why:** Fixture 12. Hard. Requires stored-then-rendered tracking.
- **Target state:** Detect a known DB-write sink with tainted input,
  followed by a known DB-read source flowing to an HTML sink.
- **Approach:** Cross-rule analysis — needs §EN-1 cross-file summaries
  AND DB-as-source models.
- **Effort:** **L** (~2 weeks).

## §RC-32 — JNDI injection (Java)

- **Target state:** `Context.lookup(taint)` is RCE.
- **Effort:** **S** (depends on §LC-7).

## §RC-33 — JWT misuse deepening — already strong

- **Current state:** ✅ algorithms:none, decode-without-verify, hardcoded
  secret with file-local variable tracking.
- **Target state:** Detect JWT signature verification with public key
  used as HMAC secret (CVE-2018-0114-style).
- **Effort:** **M** (3 days).

## §RC-34 — CORS misconfig deepening — already strong

- **Current state:** ✅ wildcard+credentials, origin:true+creds, origin
  reflection.
- **Target state:** Per-route CORS where one route is misconfigured.
- **Effort:** **S** (1 day).

## §RC-35 — Misleading-progress / dependency-confusion (CWE-1357) ✅ DONE — sha e330ed4 (2026-05-07)

- **Target state:** Flag npm package names that match common typosquats.
- **Approach:** Static list of typosquats; check `package.json`
  dependencies.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added `dependency-confusion` rule for `package.json`.
  - Checks dependencies/devDependencies/peerDependencies/optionalDependencies
    against a high-signal typosquat map.
  - Emits package-manager scoped findings with suggested canonical package
    names.

## §RC-36 — Server-side template injection deepening (CWE-1336)

- **Current state:** Flask-render-template-string + Jinja from_string
  partial.
- **Target state:** Add EJS, Handlebars, Pug, Mustache, Nunjucks shapes.
- **Effort:** **M** (3 days).

## §RC-37 — Unsafe HTML in WebView / iframe (Android+Flutter)

- **Current state:** Some Dart-side coverage.
- **Target state:** Flag `WebView.loadHtmlString(taint)` /
  `iframe.srcdoc=taint` consistently.
- **Effort:** **S** (1 day).

## §RC-38 — IPC / message channel taint (Electron, mobile)

- **Target state:** `ipcRenderer.send` with taint, `MethodChannel.invokeMethod`
  with taint, web-app `postMessage`.
- **Effort:** **M** (3 days).

## §RC-39 — Use after free / double free / null deref (C/C++)

- **Why:** Memory safety. Out of scope unless we pursue C/C++.
- **Effort:** **XL** if pursued. **0** if skipped (recommend skip).

## §RC-40 — SQL second-order injection (CWE-89 stored variant)

- **Why:** Tainted data stored to DB, retrieved later, used in another
  SQL query without escaping.
- **Effort:** **L** (~2 weeks; depends on stored-source modeling).

## §RC-41 — DoS via regex on user input (CWE-1333 specific)

- **Current state:** §RC-2 covers regex. This adds: `new RegExp(taint, 'g').test(somethingElse)`
  — attacker-controlled regex.
- **Effort:** **S** (1 day post §RC-2).

## §RC-42 — Server-side cache poisoning

- **Effort:** **L** (~1 week).

## §RC-43 — Improper certificate validation ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** Flag `rejectUnauthorized: false`, `https.Agent({ rejectUnauthorized: false })`,
  custom `tls.connect` with disabled verify.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - New rule `improper-cert-validation` (CWE-295, HIGH severity).
  - Catches three escape hatches: `rejectUnauthorized:false`,
    `NODE_TLS_REJECT_UNAUTHORIZED=0`, and stub `checkServerIdentity`
    (arrow / function returning `undefined|null|{}`).
  - Reuses new `stripLineComment` helper that walks the line tracking
    quote state — required because the naive `indexOf('//')` mistakes
    URLs (`'https://x'`) for line comments. Both this rule and
    `hardcoded-ip` now share that helper.
  - 5 positive/negative tests in `scripts/taint-engine.test.js`.

## §RC-44 — Insecure cryptographic key storage ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** `crypto.createCipher(algo, hardcodedKey)` where key
  is a string literal and algo is real.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Extended `weak-crypto-js` to flag deprecated Node
    `crypto.createCipher` / `crypto.createDecipher` calls.
  - Negative test confirms `createCipheriv` with a non-weak algorithm remains
    clean.

## §RC-45 — Cookie scope issues (Domain, Path) ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** Cookies set with `Domain: .example.com` (broader
  than needed) flag.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Extended `insecure-cookie` to flag leading-dot domain options and explain
    the subdomain blast-radius issue.
  - No-domain host-scoped cookies remain clean.

## §RC-46 — CSRF token absence

- **Target state:** Form-handling routes (POST/PUT/DELETE) without
  CSRF middleware (`csurf`, `csrf-csrf`, `next-auth`).
- **Effort:** **L** (~1 week — requires route-handler analysis).

## §RC-47 — Excessive permissions on cloud SDKs

- **Target state:** AWS SDK with `*` IAM action, GCP `cloudkms.Encrypter`
  with `*` resource.
- **Effort:** **L** (~1 week).

## §RC-48 — SSL/TLS deprecated protocols ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** `tls.createServer({ secureProtocol: 'TLSv1' })`,
  `https.request({ secureProtocol: 'TLSv1' })`.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Extended `weak-crypto-js` to flag `secureProtocol` / `minVersion`
    pinning to SSLv3, TLSv1.0, or TLSv1.1.
  - Negative test keeps `minVersion: "TLSv1.2"` clean.

## §RC-49 — Improper input validation in cryptographic operations

- **Target state:** RSA padding misconfig, AES IV reuse.
- **Effort:** **L** (~1 week).

## §RC-50 — Untrusted code injection via dynamic `import()` ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** `import(taint)` flag.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added `import` as a code-class sink (CWE-95) in
    `vscode-extension/src/taint/dataFlow.ts:_sinkForCall`.
  - Extended `injectionRule.ts`'s sink prefilter regex with `\bimport\s*\(`
    so files using dynamic import enter the AST stage.
  - Tree-sitter parses `import('./mod' + x)` as a `call_expression`
    whose callee is the `import` keyword node, so `getCallName` returns
    `"import"`. Static `import { … } from '…'` is `import_statement`
    and never reaches the call-expression sink path — covered by a
    negative test.
  - Tests in `scripts/taint-engine.test.js` (positive + negative).

## §RC-51 — Server-side request forgery via WebSocket (CWE-918)

- **Effort:** **M** (2 days).

## §RC-52 — Insecure DNS settings

- **Effort:** **S** (1 day).

## §RC-53 — Plain HTTP in mobile (App Transport Security)

- **Current state:** `plaintext-http` rule on Dart side.
- **Target state:** Same on JS side; iOS NSAllowsArbitraryLoads check.
- **Effort:** **S** (1 day).

## §RC-54 — JavaScript / TypeScript template literal injection in eval

- **Target state:** `eval(\`literal ${taint}\`)` already covered. Verify.
- **Effort:** **S** (1 day).

## §RC-55 — Stored credentials in localStorage / IndexedDB ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** `localStorage.setItem('token', x)`, `sessionStorage`.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - New `insecure-web-storage` rule flags credential-shaped keys in
    `localStorage` / `sessionStorage` writes (`setItem`, bracket assignment,
    and property assignment).
  - Benign preference keys such as `theme` remain clean.

## §RC-56 — Privacy leak — clipboard / pasteboard exposure ✅ DONE — sha f2d31ad (2026-05-07)

- **Current state:** `clipboard-exposure` rule on Dart side.
- **Target state:** JS-side `navigator.clipboard.writeText(taint)` with
  sensitive payload.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - New JS-side `clipboard-exposure` rule flags
    `navigator.clipboard.writeText(...)` when the copied expression contains
    credential-shaped identifiers.
  - `writeText(url)` stays clean; legacy `document.execCommand("copy")`
    produces only a low-confidence reminder to inspect the selected payload.

## §RC-57 — Insecure default permissions (CWE-276)

- **Target state:** `fs.chmod(p, 0o777)` etc.
- **Effort:** **S** (1 day).

## §RC-58 — Hardcoded IP addresses ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** Static IP literals in source code (cheap to detect,
  often a misconfig).
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - New rule `hardcoded-ip` (kebab-case code,
    `vscode-extension/src/rules/security/hardcodedIpRule.ts`,
    `RuleStage.fast`, CWE-547).
  - IPv4: anchored octet regex with valid-range check; ignores RFC 1918,
    RFC 6598 CGNAT, loopback, link-local, multicast, broadcast, 0.0.0.0/8,
    and the documentation ranges (TEST-NET-1/2/3, benchmark).
  - IPv6: permissive prefilter, then a structural validator
    `_parseIPv6` that handles `::` elision and exact-8-group constraint;
    skips `::`, `::1`, `fe80::/10`, `fc00::/7`, `2001:db8::/32`, `ff*`.
  - Strips `//` (and `#` for shell/Python/conf) line comments before
    matching so example IPs in docstrings don't fire.
  - Severity LOW / confidence MEDIUM — regex-only, intended as a noisy
    suggestion until paired with a "is this a config file?" gate.

## §RC-59 — Time-of-check time-of-use on cookies (login fixation)

- **Effort:** **L** (~1 week).

## §RC-60 — JWT algorithm confusion (RS256→HS256 with public key) ✅ DONE — sha e330ed4 (2026-05-07)

- **Effort:** **M** (3 days).
- **Implementation notes:**
  - Extended `jwt-misuse` to flag `jwt.verify(...)` calls that allow
    `HS256` while using public-key shaped verification material.
  - Covers PEM public-key literals and public-key named variables.

---

## Summary

That's 60 rules to author / strengthen. Each S = ~half a day, M = 2-5
days, L = 1+ weeks. Total: roughly **6 engineer-months** to implement
all rules at the listed effort budget. Combined with framework models
([02-framework-models.md](02-framework-models.md)), this is the bulk
of "catch up to CodeQL on rule count."
