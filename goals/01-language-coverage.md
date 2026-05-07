# 01 — Language coverage

For each language we currently support, this file lists the source/sink
expansions needed to match CodeQL's per-language pack. For languages we
don't yet support, it lists the bring-up cost.

CodeQL ships first-class analysis for: **JavaScript/TypeScript, Python,
Java, Go, C/C++, C#, Ruby, Swift, Kotlin**. We currently have full taint
on JS/TS, IFDS on Dart, AST grammars without taint on Python/Go/Java,
and nothing on the rest.

Read [00-engine.md](00-engine.md) first. Most language-specific work
adds rows to a registry; the engine itself is what makes those rows
meaningful.

## Status (as of 2026-05-07)

Legend: ✅ DONE | 🟡 PARTIAL | ⏳ REMAINING (default).

- ✅ Dart IFDS engine itself (covers §LC-13 architecturally; sha 9baeca2 + 21c9cbb).
  Source-set extensions and per-construct sensitivity (cascade, named args,
  field-sensitive, collection-sensitive) are tracked under §SF-14..19 in
  [09-supabase-flutter.md](09-supabase-flutter.md) and are **still pending**.
- ⏳ Every §LC-* task below — language-specific source/sink expansions are unstarted.

## Per-language status table

| Language | Grammar | Sources | Sinks | Sanitizers | Taint depth | Framework models |
|----------|---------|---------|-------|------------|-------------|-------------------|
| JavaScript | ✅ tree-sitter | ~12 categories | 10 sink kinds | regex over names | intra-procedural | none |
| TypeScript | ✅ tree-sitter | (shares JS) | (shares JS) | (shares JS) | (shares JS) | none |
| Dart | ✅ tree-sitter | ~6 patterns | ~5 sink kinds | name-based | **inter-procedural (IFDS)** | none |
| Python | ✅ tree-sitter | Flask/Django/FastAPI request fields only | partial (subprocess, eval, sql, yaml) | regex names | none | partial Flask |
| Go | ✅ tree-sitter | **none** (sink-only) | os/exec, eval-style | none | none | none |
| Java | ✅ tree-sitter | **none** (sink-only) | partial | none | none | none |
| C# | ❌ | — | — | — | — | — |
| Ruby | ❌ | — | — | — | — | — |
| Swift | ❌ | — | — | — | — | — |
| Kotlin | ❌ | — | — | — | — | — |
| C/C++ | ❌ | — | — | — | — | — |

---

## §LC-1 — Python: bring sources to parity with CodeQL

- **Why:** We have AST grammar but no source patterns for Django ORM,
  SQLAlchemy, Pyramid, Tornado, or async views.
- **Current state:** `dataFlow.ts:_isDirectSourceExpression` recognizes
  `request.args/form/values/json/cookies/headers/files/data`,
  `request.query_params/path_params`, and stdin. Misses `flask.request.values`,
  `quart.request`, `tornado.RequestHandler.get_argument`, `aiohttp.web.Request`,
  Django `request.POST`, `request.GET`, `request.FILES`, `request.META`.
- **Target state:** Every CodeQL `python/web/` source recognized.
- **Approach:** Append regexes to `_isDirectSourceExpression`. Also add
  destructured forms (`from flask import request as r`).
- **Dependencies:** None.
- **Effort:** **M** (3 days).
- **Tests:** New `test_python_web_sources.py` fixtures across Flask,
  Django, FastAPI, aiohttp, Tornado, Quart, Pyramid.
- **Risks / gotchas:** Django `request.POST` is a `QueryDict`, not a
  dict. Methods on it (`.get`, `.getlist`) all return tainted. Add the
  whole receiver as a tainted-object, not just the property accesses.

## §LC-2 — Python: SQL/ORM sinks (SQLAlchemy, Django ORM, peewee, asyncpg)

- **Why:** A real Python web app uses an ORM, not raw `cursor.execute()`.
  CodeQL's Python pack ships ORM-aware queries.
- **Current state:** Only `cursor.execute`, `subprocess.run/call/check_output/Popen`,
  `os.system/popen`, `pickle.loads/load`, `yaml.load/load_all/unsafe_load/full_load`.
- **Target state:** Recognize `Model.objects.raw()`, `Model.objects.extra(where=…)`,
  `engine.execute(text(…))`, `session.execute(text(…))`, `session.query(…).filter(…)`
  with f-strings, `cursor.executemany`, `peewee Model.raw`, `asyncpg.Connection.execute/fetch`.
- **Approach:** Extend `_sinkForCall` with the new patterns.
- **Dependencies:** None.
- **Effort:** **M** (3 days).
- **Tests:** Per-ORM fixture set.
- **Risks / gotchas:** Django's `raw()` is unsafe by default; `extra(where=)`
  is also; but `filter()` with kwargs is safe (parameterized). Don't FP on `filter()`.

## §LC-3 — Python: framework deep models (Flask/FastAPI/Django views)

- **Why:** Today we recognize `request.X` as a source but don't know
  about route handlers (`@app.route`, `@app.get`, view functions). This
  matters for return-as-sink (response body).
- **Current state:** Decorators not parsed; view functions not specially handled.
- **Target state:** `@app.route('/u')` decorated functions: any `return`
  value is treated as flowing to an HTML/JSON sink. `request` parameter
  always tainted.
- **Approach:** Walk decorators on `function_definition` nodes; if any
  is `app.route`/`app.get`/etc., the function body's `return` becomes a
  conditional sink.
- **Dependencies:** §EN-2 if also doing async views.
- **Effort:** **M** (4 days).
- **Tests:** Reflected XSS via Flask/FastAPI route. Stored XSS via
  Django template render.
- **Risks / gotchas:** FastAPI's response models often serialize through
  Pydantic — Pydantic's validation acts as a sanitizer for type-safe
  fields. Treat `request.X: Annotated[int, …]` as type-checked → safe
  for SQL/command but still tainted for HTML.

## §LC-4 — Go: source patterns (net/http, gin, echo, fiber)

- **Why:** No Go source patterns exist today, so the existing sink list
  (`os/exec.Command`, `fmt.Sprintf`, `unsafe`) is dead code.
- **Current state:** Zero source patterns in `_isDirectSourceExpression`
  matching Go shapes.
- **Target state:** Recognize `r.URL.Query()`, `r.Form`, `r.PostForm`,
  `r.MultipartForm`, `r.Body`, `r.Header.Get(k)`, `r.Cookie(k)`,
  `mux.Vars(r)`, gin `c.Query(k)`/`c.Param(k)`/`c.PostForm(k)`/`c.Bind(&x)`,
  echo `c.QueryParam(k)`/`c.FormValue(k)`/`c.Bind(&x)`, fiber `c.Query(k)`.
- **Approach:** Same pattern as Python sources — append to the regex
  list. Plus: tracked variable from `var r *http.Request` parameter.
- **Dependencies:** None.
- **Effort:** **M** (3 days).
- **Tests:** Per-framework fixture.
- **Risks / gotchas:** Go's struct receivers are method targets. Track
  receiver-as-source for `(r *Request)`-style methods.

## §LC-5 — Go: sinks (database/sql, html/template, os/exec)

- **Why:** Sinks beyond `os/exec` are missing — no `db.Query`,
  `template.HTML`, `template.URL`, etc.
- **Current state:** `os/exec.Command`, eval-style only.
- **Target state:** `db.Query/QueryRow/Exec`, `tx.Query/Exec`,
  `template.HTML(taint)`, `template.URL(taint)`, `template.JS(taint)`,
  `template.CSS(taint)`, `unsafe.Pointer`, `fmt.Sprintf` + sink (e.g.
  passed to db.Query) chain.
- **Approach:** Extend `_sinkForCall` with go-style receivers (the
  `database/sql.DB` and `database/sql.Tx` types).
- **Dependencies:** §EN-6 (type-aware) makes this much more accurate
  but isn't required for a first cut.
- **Effort:** **M** (4 days).
- **Tests:** Per-sink fixture set.
- **Risks / gotchas:** `db.Query("SELECT ... ?", arg)` IS parameterized.
  Don't FP. Detect the `?` placeholder pattern and the additional args.

## §LC-6 — Java: sources (Servlet, JAX-RS, Spring MVC)

- **Why:** Same as Go — no source patterns. Sink-only registration is
  dead code on Java.
- **Current state:** No Java source patterns.
- **Target state:** Recognize `request.getParameter(k)`,
  `request.getHeader(k)`, `request.getCookies()`, `request.getPart(k)`,
  `request.getInputStream()`, `request.getReader()`, JAX-RS
  `@PathParam("…")`, `@QueryParam("…")`, `@FormParam("…")`,
  `@HeaderParam("…")`, `@CookieParam("…")`, `@BeanParam`, Spring MVC
  `@RequestParam`, `@PathVariable`, `@RequestHeader`, `@CookieValue`,
  `@RequestBody`.
- **Approach:** Same as §LC-1 / §LC-4. Annotation-based sources need
  AST walking of `formal_parameter` nodes for annotations.
- **Dependencies:** None.
- **Effort:** **M** (4 days).
- **Tests:** Per-framework fixture.
- **Risks / gotchas:** `@RequestBody` deserializes JSON into a typed
  POJO; the POJO's fields are tainted but type-checked.

## §LC-7 — Java: sinks (JDBC, JPA, JNDI, JMS, Hibernate, Mybatis)

- **Why:** No Java sinks today. CodeQL's Java pack covers
  hundreds of CWEs across these frameworks.
- **Current state:** Zero Java sinks recognized.
- **Target state:** `Statement.executeQuery/executeUpdate/execute`,
  `PreparedStatement.executeQuery` (when constructed with concatenation),
  `EntityManager.createQuery(jpql)`, `Session.createSQLQuery`,
  `Hibernate.createNativeQuery`, `MyBatis @Select` annotation values,
  `JNDI Context.lookup(taint)`, `JMS Session.createTextMessage(taint)`,
  `Runtime.exec(taint)`, `ProcessBuilder(taint).start()`.
- **Approach:** Append patterns. Method invocations on `Statement` /
  `EntityManager` types are easy to spot syntactically.
- **Dependencies:** §EN-6 (type-aware) helps a lot.
- **Effort:** **L** (~1 week).
- **Tests:** Per-sink fixture set with parameterized-query negative tests.
- **Risks / gotchas:** Hibernate's HQL is not the same as JPQL is not
  the same as SQL. They're all injection-prone but the keyword sets
  differ. Use a permissive keyword list.

## §LC-8 — Java: framework models (Spring Security, Spring Boot)

- **Why:** Spring is the dominant Java web framework. Missing it means
  most enterprise Java apps are unscanned.
- **Current state:** Nothing.
- **Target state:** Recognize Spring Boot's auto-configuration shape;
  `@Controller`, `@RestController`, `@Service`, `@Repository`
  annotations seed taint at parameter level. Spring Security's
  `@PreAuthorize` is a **barrier** — code inside is presumed authorized.
- **Approach:** Annotation walk (same as §LC-6) plus a barrier rule
  (§EN-4).
- **Dependencies:** §LC-6, §EN-4.
- **Effort:** **L** (~10 days).
- **Tests:** Per-annotation fixture.
- **Risks / gotchas:** Spring's `@RequestMapping` value parsing is
  complex; don't try to reproduce path-template logic. Just recognize
  the annotation as marking the function as a route.

## §LC-9 — C#: bring up tree-sitter + AST

- **Why:** C# is the largest language we don't support. .NET, ASP.NET
  Core, Entity Framework all visible.
- **Current state:** Zero — no grammar registered, no rules.
- **Target state:** `tree-sitter-c-sharp` registered in
  `vscode-extension/src/ast/parser.ts`. Source/sink patterns for ASP.NET
  Core (`HttpContext.Request`), Entity Framework (`db.Database.ExecuteSqlRaw`,
  `FromSqlRaw`).
- **Approach:**
  1. Add the grammar via `tree-sitter-wasms` (the package may not ship
     C# — fall back to building from upstream `tree-sitter-c-sharp`
     and bundling the WASM).
  2. Adapt `_sinkForCall` and source patterns.
  3. Wire one rule: `csharp-sql-injection` covering EF Core raw queries.
- **Dependencies:** None.
- **Effort:** **L** (~3 weeks for grammar bring-up + first rule).
- **Tests:** EF Core fixture suite.
- **Risks / gotchas:** C# has lots of language features (LINQ, async,
  nullable refs). Just parse — don't try to model LINQ semantics in a
  first cut.

## §LC-10 — Ruby: bring up + Rails models

- **Why:** Rails is one of the dominant web frameworks; CodeQL has a
  Ruby pack.
- **Current state:** Nothing.
- **Target state:** `tree-sitter-ruby` registered. Sources from
  `params`, `request.GET`, ActiveRecord sinks (`User.where("name = '#{name}'")`,
  `User.find_by_sql(taint)`), command sinks (`exec`, `system`,
  backticks).
- **Approach:** Same shape as §LC-9.
- **Dependencies:** None.
- **Effort:** **L** (~3 weeks).
- **Tests:** Rails ActiveRecord fixture.
- **Risks / gotchas:** Ruby's metaprogramming makes some sinks hard
  to trace — don't try.

## §LC-11 — Swift: iOS focus

- **Why:** iOS apps are a real audience and CodeQL has limited Swift
  coverage. Real differentiation potential.
- **Current state:** Nothing.
- **Target state:** `tree-sitter-swift` grammar; sources from
  `URLSession` data tasks, iOS deep links (`UIApplicationDelegate.application:openURL:`),
  `WKWebView` injection sinks, KeyChain misuse.
- **Approach:** Same shape as §LC-9.
- **Dependencies:** None.
- **Effort:** **XL** (~6 weeks for full Swift+iOS).
- **Tests:** iOS fixture suite (deep link + WebView XSS).
- **Risks / gotchas:** Swift type system is complex; lean on simple
  receiver-name heuristics initially.

## §LC-12 — Kotlin: Android focus

- **Why:** Android apps. Pairs with §LC-11.
- **Current state:** Nothing.
- **Target state:** `tree-sitter-kotlin` grammar. Sources from `Intent`
  (`getIntent().getStringExtra(k)`), `Bundle`. Sinks: SQLite, WebView
  `loadUrl(tainted)`, `evaluateJavascript`, file I/O.
- **Approach:** Same shape as §LC-9.
- **Dependencies:** None.
- **Effort:** **XL** (~6 weeks).
- **Tests:** Android Intent / WebView fixture suite.
- **Risks / gotchas:** Android-specific permission model is complex. Don't
  model it; flag the sink.

## §LC-13 — C / C++: bring up

- **Why:** Half of CodeQL's value is on C/C++ (memory safety, format
  strings, integer overflow). Different domain than web SAST.
- **Current state:** Nothing.
- **Target state:** `tree-sitter-c` and `tree-sitter-cpp` registered.
  Memory-safety rules: use-after-free (CWE-416), double-free (CWE-415),
  buffer overflow (CWE-120), format string (CWE-134),
  integer overflow (CWE-190), null deref (CWE-476).
- **Approach:** Memory analysis is genuinely different from taint
  analysis. Either:
  (a) Add rules that recognize known-bad patterns (`gets()`, `strcpy`,
      `sprintf` with `%s` and user input).
  (b) Skip C/C++ entirely and stay focused on managed languages.
- **Recommendation:** Skip in the first round. CodeQL's C/C++ pack is
  10+ years deep; we cannot match it. Document as a non-goal in
  [10-non-goals.md](10-non-goals.md).
- **Effort:** **XL** if pursued; **0** if skipped.

## §LC-14 — Dart: extend IFDS source/sink coverage

- **Why:** Our Dart IFDS engine is real but its source/sink registry is
  thin (CLI args, stdin, network response, plus a few sinks).
- **Current state:** `vscode-extension/src/taint/ifdsBuilder.ts` registers
  source patterns from `dataFlow.ts`'s shared list. Limited Flutter coverage.
- **Target state:** Add Flutter-specific sources: `TextEditingController.text`,
  `await rootBundle.loadString(asset)` (semi-source — file content),
  `MethodChannel.invokeMethod` returns, deep links via `getInitialLink`,
  push notification payloads, biometric prompts. Plus sinks:
  `WebView.loadUrl`, `WebView.evaluateJavascript`, `Process.run`,
  `Process.start`, sqflite `rawQuery`, Hive `box.put` with raw keys.
- **Approach:** Extend the shared registry. Each entry carries a
  `lang: 'dart' | 'js'` tag.
- **Dependencies:** None.
- **Effort:** **M** (5 days).
- **Tests:** Flutter-app fixture suite (deep_link, webview, biometric).
- **Risks / gotchas:** `Process.run` already covered as a sink for JS;
  reuse the registration but with Dart-specific receiver typing.

## §LC-15 — Dart: virtual dispatch beyond last-name resolution

- **Why:** Today the IFDS engine resolves method dispatch by last name
  only (limitation documented in `README.md`). Subclass overrides aren't
  modeled.
- **Current state:** Documented limitation.
- **Target state:** Class hierarchy walked; subclass methods override
  parents' callsites correctly.
- **Approach:** Mirror §EN-11 but in `ifdsBuilder.ts`. Build a
  per-class method table; resolve method calls through the type when
  available.
- **Dependencies:** None — internal to Dart engine.
- **Effort:** **L** (~2 weeks).
- **Tests:** Dart class-hierarchy fixture.
- **Risks / gotchas:** Mixins and `extends` chains. Bound to 5 levels deep.

## §LC-16 — TypeScript: type-aware sink filtering (already a row in §EN-6)

See §EN-6.

## §LC-17 — JavaScript: support for older runtimes (Node 14+, browsers)

- **Why:** A scanner that only catches modern syntax misses real apps.
- **Current state:** tree-sitter-javascript handles ES2015+. Some older
  patterns (`var`, IIFE, prototype-based classes) work but newer ones
  (top-level await, optional chaining, nullish coalescing) need
  verification.
- **Target state:** Documented coverage table; tests for each ES feature.
- **Approach:** Build a fixture corpus (one file per ES feature). Verify
  taint through each.
- **Dependencies:** None.
- **Effort:** **S** (1 day for the audit).
- **Tests:** `test/fixtures/syntax-coverage/`.
- **Risks / gotchas:** None.
