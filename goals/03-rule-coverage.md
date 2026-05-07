# 03 — Rule coverage

Every CWE class CodeQL ships a query for that we don't yet have. Each
entry is one rule. Most are S–M effort and the gap closure scales linearly.

We currently have 24 rules covering ~10 CWE classes. CodeQL's JS pack
alone ships 250+ queries. This file walks the gap.

For shape and registration steps, mirror existing rules under
[`vscode-extension/src/rules/`](../vscode-extension/src/rules/).

---

## §RC-1 — Prototype pollution (CWE-1321) ✅ HIGH PRIORITY

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

## §RC-2 — ReDoS / catastrophic backtracking (CWE-1333) ✅ HIGH PRIORITY

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
- **Target state:** New rule `log-injection`. Detect tainted strings
  reaching `console.log/warn/error/info`, Winston `logger.info(taint)`,
  Pino, Bunyan, etc. — without `\r` / `\n` stripping.
- **Approach:** Sink kind `log`. Flag tainted args. Sanitizers:
  any function whose name contains `escape` / `redact` / regex
  containing `\r\n`.
- **Dependencies:** §EN-2 (Promise) for Winston async loggers.
- **Effort:** **S** (1 day).
- **Tests:** `console.log(taint)`, Winston, Pino fixtures.

## §RC-4 — Header injection / response splitting (CWE-113)

- **Why:** Tainted data into `Set-Cookie` / `Location` headers can
  forge new headers via `\r\n`.
- **Current state:** No rule.
- **Target state:** Detect tainted strings reaching `res.setHeader(name, taint)`,
  `res.cookie(name, taint, …)` with `\r\n` not stripped, `res.location(taint)`.
- **Approach:** Sink kind `header`. Sanitizer: `encodeURIComponent`,
  `replace(/\r\n/, '')`.
- **Dependencies:** None.
- **Effort:** **S** (1 day).

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

## §RC-13 — Tabnabbing (CWE-1022)

- **Why:** `target="_blank"` without `rel="noopener noreferrer"` lets
  the destination access `window.opener`.
- **Current state:** No rule.
- **Target state:** Detect JSX `<a target="_blank">` without `rel`,
  HTML files, `window.open` without `noopener`.
- **Effort:** **S** (1 day).

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

## §RC-18 — Information exposure through exception (CWE-209)

- **Target state:** Detect `res.send(err.message)` / `res.send(err.stack)`
  patterns.
- **Effort:** **S** (1 day).

## §RC-19 — Cleartext transmission of sensitive info (CWE-319)

- **Why:** `http://` instead of `https://` in HTTP clients.
- **Current state:** Partial — we don't have a dedicated rule.
- **Target state:** Flag `fetch('http://...')` patterns where `https://`
  would be expected (production URLs).
- **Effort:** **S** (1 day).

## §RC-20 — Weak cryptography variants (CWE-327)

- **Why:** We have `weak-crypto` rule on the Dart side. JS side missing.
- **Target state:** Detect `crypto.createCipher('des', …)` /
  `crypto.createHash('md5')` / `crypto.createHash('sha1')` in security
  contexts.
- **Effort:** **S** (1 day).

## §RC-21 — Hardcoded credentials variants (already strong)

- **Current state:** `hardcoded-secrets`, `generic-secret` cover AWS,
  GCP, JWT, generic.
- **Target state:** Add Stripe, Twilio, SendGrid, OpenAI, Anthropic,
  Slack, GitHub, Azure, Heroku token shapes.
- **Effort:** **S** (1 day per provider; ongoing).

## §RC-22 — Insecure cookie variants (CWE-1004/614/352) — already covered

- **Current state:** ✅ Done. Track maintenance only.

## §RC-23 — Insecure randomness (CWE-338) — already covered

- **Current state:** ✅ Done.

## §RC-24 — Path traversal variants (CWE-22)

- **Current state:** Dart side has `path-traversal` rule. JS side
  doesn't have a dedicated rule but covers it via `injection-flaw`
  with sink kind `path`.
- **Target state:** Dedicated `path-traversal` rule for JS that
  recognizes `path.join(__dirname, taint)` as traversal-prone unless
  guarded.
- **Effort:** **S** (1 day).

## §RC-25 — Symlink following (CWE-59)

- **Target state:** Flag `fs.readFile(path, options)` where path is
  user-controlled and `options` doesn't include `withFileTypes` /
  symlink-rejection check.
- **Effort:** **M** (2 days).

## §RC-26 — Type confusion (CWE-843) — JS specific

- **Target state:** `typeof x === 'string'` on values that flow into
  numeric operations.
- **Effort:** **M** (3 days).

## §RC-27 — Format string (CWE-134) — Python's % and f-strings

- **Target state:** Detect `'admin: %s' % taint` and `f"admin: {taint}"`
  flowing to log/SQL/command sinks.
- **Effort:** **S** (1 day).

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

## §RC-35 — Misleading-progress / dependency-confusion (CWE-1357)

- **Target state:** Flag npm package names that match common typosquats.
- **Approach:** Static list of typosquats; check `package.json`
  dependencies.
- **Effort:** **S** (1 day).

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

## §RC-43 — Improper certificate validation

- **Target state:** Flag `rejectUnauthorized: false`, `https.Agent({ rejectUnauthorized: false })`,
  custom `tls.connect` with disabled verify.
- **Effort:** **S** (1 day).

## §RC-44 — Insecure cryptographic key storage

- **Target state:** `crypto.createCipher(algo, hardcodedKey)` where key
  is a string literal and algo is real.
- **Effort:** **S** (1 day).

## §RC-45 — Cookie scope issues (Domain, Path)

- **Target state:** Cookies set with `Domain: .example.com` (broader
  than needed) flag.
- **Effort:** **S** (1 day).

## §RC-46 — CSRF token absence

- **Target state:** Form-handling routes (POST/PUT/DELETE) without
  CSRF middleware (`csurf`, `csrf-csrf`, `next-auth`).
- **Effort:** **L** (~1 week — requires route-handler analysis).

## §RC-47 — Excessive permissions on cloud SDKs

- **Target state:** AWS SDK with `*` IAM action, GCP `cloudkms.Encrypter`
  with `*` resource.
- **Effort:** **L** (~1 week).

## §RC-48 — SSL/TLS deprecated protocols

- **Target state:** `tls.createServer({ secureProtocol: 'TLSv1' })`,
  `https.request({ secureProtocol: 'TLSv1' })`.
- **Effort:** **S** (1 day).

## §RC-49 — Improper input validation in cryptographic operations

- **Target state:** RSA padding misconfig, AES IV reuse.
- **Effort:** **L** (~1 week).

## §RC-50 — Untrusted code injection via dynamic `import()`

- **Target state:** `import(taint)` flag.
- **Effort:** **S** (1 day).

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

## §RC-55 — Stored credentials in localStorage / IndexedDB

- **Target state:** `localStorage.setItem('token', x)`, `sessionStorage`.
- **Effort:** **S** (1 day).

## §RC-56 — Privacy leak — clipboard / pasteboard exposure

- **Current state:** `clipboard-exposure` rule on Dart side.
- **Target state:** JS-side `navigator.clipboard.writeText(taint)` with
  sensitive payload.
- **Effort:** **S** (1 day).

## §RC-57 — Insecure default permissions (CWE-276)

- **Target state:** `fs.chmod(p, 0o777)` etc.
- **Effort:** **S** (1 day).

## §RC-58 — Hardcoded IP addresses

- **Target state:** Static IP literals in source code (cheap to detect,
  often a misconfig).
- **Effort:** **S** (1 day).

## §RC-59 — Time-of-check time-of-use on cookies (login fixation)

- **Effort:** **L** (~1 week).

## §RC-60 — JWT algorithm confusion (RS256→HS256 with public key)

- **Effort:** **M** (3 days).

---

## Summary

That's 60 rules to author / strengthen. Each S = ~half a day, M = 2-5
days, L = 1+ weeks. Total: roughly **6 engineer-months** to implement
all rules at the listed effort budget. Combined with framework models
([02-framework-models.md](02-framework-models.md)), this is the bulk
of "catch up to CodeQL on rule count."
