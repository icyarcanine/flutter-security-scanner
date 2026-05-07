# 02 — Framework models

CodeQL's edge over us on JS/TS comes mostly from framework models. A
"framework model" is a registry entry telling the engine: "this function
returns user-controlled data" or "this method is an HTML sink" or "this
object's `body` field is tainted by default".

Each framework needs source/sink/sanitizer entries. Most entries are
~5 lines each. The total framework surface is dozens of frameworks
across the languages we care about. **This is the highest-leverage,
most-tractable area of the catch-up.**

## How to add a framework

1. Create `vscode-extension/src/taint/frameworks/<name>.ts`.
2. Export an `FrameworkModel` shape:
   ```ts
   export const expressModel: FrameworkModel = {
     id: 'express',
     detect: (ctx) => ctx.hasDependency('express'),
     sources: [
       { match: /^req\.(body|query|params|cookies|headers|file|files)/, kind: 'http-request' },
       { match: /^req\.params\.(\w+)$/, kind: 'http-request' },
     ],
     sinks: [
       { receiver: 'res', method: 'send', kind: 'html', argIndex: 0 },
       { receiver: 'res', method: 'json', kind: 'html', argIndex: 0 },
       { receiver: 'res', method: 'redirect', kind: 'redirect', argIndex: 0 },
       { receiver: 'res', method: 'render', kind: 'template', argIndex: 1 },
     ],
     sanitizers: [
       { match: /^validator\.escape$/, kind: 'name-only' },
     ],
   };
   ```
3. Register in `vscode-extension/src/taint/frameworks/index.ts`.
4. Each `FrameworkModel.detect` runs once per scan; if true, the
   sources/sinks/sanitizers are merged into the global registry.
5. Add fixtures under `test/fixtures/<framework>/` and unit tests in
   `scripts/taint-engine.test.js`.

The framework registry should be lazy — only models for detected
frameworks contribute, so unrelated patterns don't FP.

## §FM-1 — Express.js (Node)

- **Why:** Most ubiquitous Node web framework. CodeQL ships an
  Express model.
- **Current state:** We recognize `req.body/query/params/cookies/headers`
  via the strong-source heuristic, but `res.send` / `res.redirect` /
  `res.render` aren't sinks; routes via `app.get/post/etc.` aren't
  detected; middleware chains aren't traced.
- **Target state:** Express's full source/sink set per the model shape
  above. Fixture 10 in COMPARISON.md flips from FN to HIGH.
- **Approach:** As described in "How to add a framework" above.
  Detection: presence of `import 'express'` or `require('express')` in
  the file.
- **Dependencies:** None.
- **Effort:** **M** (3 days).
- **Tests:** New `test/fixtures/express/` with route handlers covering
  XSS via res.send, redirect via res.redirect, SSRF via fetch in handler.
- **Risks / gotchas:** Middleware chains (`app.use`) — assume the
  middleware can taint or sanitize anything. Document as a limitation.

## §FM-2 — Koa (Node)

- **Current state:** Nothing.
- **Target state:** `ctx.request.body/query/params`, `ctx.body = …` is
  HTML sink, `ctx.redirect`, `ctx.render`.
- **Effort:** **M** (2 days).

## §FM-3 — Fastify (Node)

- **Current state:** Nothing.
- **Target state:** `request.body/query/params`, `reply.send`, `reply.redirect`.
- **Effort:** **M** (2 days).

## §FM-4 — Hapi (Node)

- **Current state:** Nothing.
- **Target state:** `request.payload/query/params`, `h.response()`,
  `h.redirect()`.
- **Effort:** **M** (2 days).

## §FM-5 — NestJS (Node)

- **Current state:** Nothing.
- **Target state:** Decorator-based: `@Body() body`, `@Query()`,
  `@Param()`, `@Headers()`. `res.send` style sinks.
- **Approach:** Decorator walking is required. NestJS uses class methods
  with parameter decorators.
- **Effort:** **L** (5 days).

## §FM-6 — Restify (Node)

- **Current state:** Nothing.
- **Target state:** `req.params/body/query`, `res.send`.
- **Effort:** **S** (1 day).

## §FM-7 — Next.js (server-side)

- **Why:** Fast-growing in adoption. Server-side rendering creates
  XSS surfaces.
- **Current state:** Nothing.
- **Target state:** API routes (`pages/api/*`, `app/api/*`),
  `getServerSideProps`, server actions. Sources: route's `req`/`request`.
  Sinks: `res.send`, `res.json`, JSX returned from server components.
- **Effort:** **L** (~1 week).

## §FM-8 — Remix

- **Current state:** Nothing.
- **Target state:** `loader`/`action` `request` parameter, `Response`
  body sink.
- **Effort:** **M** (3 days).

## §FM-9 — Astro / SvelteKit

- **Current state:** Nothing.
- **Target state:** Per-framework SSR taint shapes.
- **Effort:** **M** each (~3 days each).

## §FM-10 — AWS Lambda / API Gateway / SAM

- **Why:** Serverless is dominant for Node back-ends.
- **Current state:** Nothing.
- **Target state:** `event.body/queryStringParameters/pathParameters/headers/requestContext`,
  return value as response.
- **Effort:** **M** (2 days).

## §FM-11 — Cloudflare Workers / Vercel Edge

- **Current state:** Nothing.
- **Target state:** `Request.body/url/headers`, `Response`.
- **Effort:** **S** (1 day).

## §FM-12 — Serverless Framework / Architect

- **Current state:** Nothing.
- **Target state:** Detection via `serverless.yml` presence; same
  `event` shape as Lambda.
- **Effort:** **S** (1 day).

## §FM-13 — Django (Python)

- **Why:** Most-deployed Python framework. CodeQL has deep Django models.
- **Current state:** Generic Python `request.X` sources work; Django ORM
  not modeled.
- **Target state:** ORM sinks (`raw()`, `extra(where=)`), template-tag
  XSS, decorator-based view recognition.
- **Effort:** **L** (~1 week).

## §FM-14 — Flask (Python)

- **Current state:** Some sources work via Python generic. Sinks not
  registered.
- **Target state:** `flask.request` source, `render_template_string`
  sink (already partially), `Markup()` is a sanitizer.
- **Effort:** **M** (3 days).

## §FM-15 — FastAPI (Python)

- **Current state:** Some sources via Python generic.
- **Target state:** Pydantic-validated sources are TYPE-CHECKED → safe
  for SQL/command but tainted for HTML.
- **Effort:** **M** (4 days).

## §FM-16 — aiohttp / Tornado / Quart / Pyramid (Python)

- **Effort each:** **M** (2 days each).

## §FM-17 — Spring Boot / Spring MVC (Java)

- **Why:** Dominant Java framework.
- **Effort:** **L** (2 weeks; depends on §LC-6).

## §FM-18 — JAX-RS (Jakarta EE) (Java)

- **Effort:** **M** (1 week).

## §FM-19 — Quarkus / Micronaut (Java)

- **Effort:** **M** (1 week).

## §FM-20 — Gin / Echo / Fiber / chi (Go)

- **Effort each:** **M** (2 days each).

## §FM-21 — net/http stdlib (Go)

- **Effort:** **M** (3 days).

## §FM-22 — Rails (Ruby)

- **Effort:** **L** (depends on §LC-10).

## §FM-23 — ASP.NET Core (C#)

- **Effort:** **L** (depends on §LC-9).

## §FM-24 — React (XSS sinks)

- **Why:** `dangerouslySetInnerHTML` is recognized today. React Server
  Components introduce new sinks.
- **Current state:** Partial.
- **Target state:** `dangerouslySetInnerHTML`, `__html` prop, server
  action return values that hit DOM.
- **Effort:** **M** (3 days).

## §FM-25 — Vue / Angular / Svelte

- **Why:** Each has own template injection surfaces (`v-html`, raw
  bindings, `[innerHTML]`).
- **Effort each:** **M** (2 days each).

---

## ORM models (not framework, but same shape)

## §FM-30 — Prisma (Node, TypeScript)

- **Why:** Fast-growing modern ORM.
- **Current state:** `prismaClient.query` recognized as SQL receiver
  via name heuristic. `$queryRaw`/`$executeRaw` not specially modeled.
- **Target state:** `prismaClient.$queryRaw\`tainted\`` is SQL-injection
  prone (tagged template). `$queryRawUnsafe` is unconditionally a sink.
- **Effort:** **M** (3 days).

## §FM-31 — TypeORM / Sequelize / Drizzle / MikroORM / Knex / Bookshelf

- **Effort each:** **M** (2 days each).

## §FM-32 — Mongoose / MongoDB driver

- **Why:** NoSQL injection surface beyond what we already detect.
- **Current state:** Mongo sinks via name match; `$where`/`$function`/
  `$accumulator` already modeled.
- **Target state:** Add `$expr`, `$regex` tainted-input detection.
- **Effort:** **S** (1 day).

## §FM-33 — Database driver direct: pg, mysql2, mssql, oracledb, sqlite3

- **Effort each:** **S** (half a day each).

---

## §FM-50 — Framework auto-detection registry

- **Why:** A framework model only contributes when its `detect()`
  returns true. The default detector reads `package.json` dependencies.
- **Current state:** No `FrameworkModel` infrastructure exists.
- **Target state:** A central registry that runs `detect()` once per
  scan and merges enabled models' source/sink lists into the engine
  registry.
- **Approach:** New `vscode-extension/src/taint/frameworks/index.ts`.
  `FrameworkContext` exposes `hasDependency(name)`, `hasFile(globPattern)`,
  `hasImport(specifier)`. Each model returns its enabled state.
- **Dependencies:** None code-side; precondition for all §FM-1 .. §FM-33.
- **Effort:** **M** (3 days for the registry; ongoing for models).
- **Tests:** New section in `scripts/taint-engine.test.js`:
  `framework-detection-respects-package-json`, `framework-models-merge-without-collision`.
- **Risks / gotchas:**
  - Don't load all models eagerly — laziness matters for memory.
  - Two models with conflicting sink kinds for the same call site:
    last-write-wins, but log a warning.
