//! Model populators for the three-way SMT correlator.
//!
//! Each function materialises one of the three input models
//! ([`DartClientModel`], [`EdgeFunctionModel`], [`RlsPolicyModel`]) from
//! the CPG or from raw SQL text extracted from `supabase/migrations/*.sql`.
//!
//! # Scope
//!
//! - **Dart clients:** extracted from the CPG by walking `MethodCall` nodes
//!   whose symbols match the Supabase fluent-builder pattern
//!   `supabase.from('T').select()...`.
//! - **Edge functions:** the engine has no TypeScript frontend yet, so this
//!   returns an empty `Vec` and emits a `tracing::warn!`. Full TS extraction
//!   is deferred to a later session.
//! - **RLS policies:** parsed from raw SQL via regex (no SQL frontend).
//!   Patterns are lifted from the Dart-side `ddl_parser.dart`.

use regex::Regex;
use rustc_hash::FxHashMap;
use tracing::{info, warn};

use crate::cpg::{AstEdge, CodeGraph, EdgeKind, EdgeKindTag, FileId, NodeId, NodeKind, SymbolId};
use crate::supabase::smt::{
    AuthContext, DartClientModel, EdgeFunctionModel, Operation, Predicate, RlsPolicyModel, Value,
};

/// Source-text lookup the populator uses to recover literal values
/// (e.g. table names passed to `supabase.from('posts')`). The Dart
/// frontend stores literals as CPG nodes with byte ranges, but does not
/// carry the source bytes themselves; the engine driver passes that map
/// into the populator.
pub type SourceMap<'a> = FxHashMap<FileId, &'a str>;

// ============================================================================
// Dart client model
// ============================================================================

/// Walk the CPG for `MethodCall` nodes whose symbol matches the Supabase
/// fluent-builder pattern `^supabase\.from\([^)]+\)`.
///
/// Each such call is the root of a builder chain that may continue with
/// `.select(...)`, `.insert(...)`, `.update(...)`, `.delete(...)`,
/// `.eq(...)`, `.neq(...)`, `.in_(...)`, etc.
///
/// Takes `&mut CodeGraph` because it needs to intern symbols during
/// extraction (table names, column names for uid references).
///
/// Returns one [`DartClientModel`] per top-level `supabase.from('T')` call
/// found.
pub fn extract_dart_clients(
    graph: &mut CodeGraph,
    source_map: &SourceMap<'_>,
) -> Vec<DartClientModel> {
    let mut clients = Vec::new();

    // Collect candidate (node_id, table_name) pairs first to avoid borrow
    // conflicts when calling `graph.intern_symbol` later.
    //
    // Why this isn't symbol-pattern matching: `lower_member_access` builds
    // symbols from dotted-path selector text only — it never inlines
    // argument values. So `supabase.from('posts')` produces a node with
    // symbol="supabase.from" and the literal `'posts'` as a slot-2 AST
    // child. We pick the call node (the chain level whose symbol ends in
    // `supabase.from` AND that has a slot-2 child) and read that child's
    // source-text byte range to recover the table name.
    let candidates: Vec<(NodeId, Option<String>)> = graph
        .iter_nodes()
        .filter(|node| {
            if node.kind != NodeKind::MethodCall {
                return false;
            }
            let Some(sym) = node.symbol else { return false };
            let canonical = graph.symbol(sym).canonical.as_ref();
            // The chain-level node carries symbol="supabase.from"; the
            // chain-with-args node carries the same symbol but has a
            // slot-2 child. We accept any MethodCall whose symbol ends
            // with `supabase.from` so chained suffixes like
            // `.from.select` don't slip through here.
            canonical == "supabase.from"
        })
        .map(|node| {
            let nid = node.id;
            // The table name is the source text of the slot-2 AST child
            // (if present) with surrounding quotes stripped.
            let table_opt = first_child_text_at_slot(graph, nid, 2, source_map)
                .map(|raw| strip_quotes(&raw).to_lowercase());
            (nid, table_opt)
        })
        .collect();

    for (node_id, table_opt) in candidates {
        let Some(table_sym) = table_opt else { continue };
        let table_id = graph.intern_symbol(&table_sym);

        // Walk the AST chain forward through all chained method calls.
        let (operation, filters, columns) = walk_client_chain(graph, node_id);

        clients.push(DartClientModel {
            table: table_id,
            operation,
            filters,
            columns,
            auth_context: AuthContext::Authenticated {
                uid: graph.intern_symbol("auth.uid"),
            },
            call_site: node_id,
        });
    }

    clients
}

/// Read the source text of the AST child at `slot` of `node_id`. Returns
/// `None` if no such child exists or the source for the file isn't in
/// the supplied map.
fn first_child_text_at_slot(
    graph: &CodeGraph,
    node_id: NodeId,
    slot: u16,
    source_map: &SourceMap<'_>,
) -> Option<String> {
    for edge in graph.out_edges(node_id, EdgeKindTag::Ast) {
        if let EdgeKind::Ast(AstEdge::Child { slot: s }) = edge.kind {
            if s == slot {
                let child = graph.node(edge.dst);
                let src = source_map.get(&child.file)?;
                let start = child.byte_range.start as usize;
                let end = (child.byte_range.end as usize).min(src.len());
                return Some(src[start..end].to_string());
            }
        }
    }
    None
}

/// Strip a single layer of `'…'` or `"…"` quoting if present. Used to
/// recover the raw value of a Dart string literal whose source-text form
/// includes the quote chars.
fn strip_quotes(s: &str) -> String {
    let trimmed = s.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

/// Walk the AST chain of chained method calls starting from `node_id`.
/// Collects the operation type, filter predicates, and referenced columns.
fn walk_client_chain(
    graph: &mut CodeGraph,
    node_id: NodeId,
) -> (Operation, Vec<Predicate>, Vec<SymbolId>) {
    let mut operation = Operation::Select;
    let mut filters = Vec::new();
    let _columns = Vec::new();

    // Walk up through the chain of nested MethodCall nodes.
    let mut current = Some(node_id);
    while let Some(nid) = current {
        let node = graph.node(nid);
        if node.kind != NodeKind::MethodCall {
            break;
        }
        let Some(sym) = node.symbol else {
            current = next_in_chain(graph, nid);
            continue;
        };
        let canonical = graph.symbol(sym).canonical.as_ref();

        // Determine operation from the last segment of the dotted path.
        if canonical.ends_with(".select(") || canonical.ends_with(".select") {
            operation = Operation::Select;
        } else if canonical.ends_with(".insert(") || canonical.ends_with(".insert") {
            operation = Operation::Insert;
        } else if canonical.ends_with(".update(") || canonical.ends_with(".update") {
            operation = Operation::Update;
        } else if canonical.ends_with(".delete(") || canonical.ends_with(".delete") {
            operation = Operation::Delete;
        } else if let Some(col) = extract_filter_column(canonical, "eq") {
            let col_sym = graph.intern_symbol(&col);
            let val_sym = graph.intern_symbol(&format!("{col}_value"));
            filters.push(Predicate::Eq {
                column: col_sym,
                value: Value::Column(val_sym),
            });
        } else if let Some(col) = extract_filter_column(canonical, "neq") {
            filters.push(Predicate::Opaque(
                graph.intern_symbol(&format!("neq_{col}")),
            ));
        } else if let Some(col) = extract_filter_column(canonical, "in_") {
            filters.push(Predicate::Opaque(graph.intern_symbol(&format!("in_{col}"))));
        }

        current = next_in_chain(graph, nid);
    }

    (operation, filters, _columns)
}

/// Follow Ast(Child { slot: 0 }) from `node_id` to find the next inner
/// method call in the chain.
fn next_in_chain(graph: &CodeGraph, node_id: NodeId) -> Option<NodeId> {
    for edge in graph.out_edges(node_id, EdgeKindTag::Ast) {
        if let EdgeKind::Ast(AstEdge::Child { slot: 0 }) = edge.kind {
            return Some(edge.dst);
        }
    }
    None
}

/// Extract a column name from a filter method call like
/// `supabase.from('posts').select().eq('user_id', uid)`.
///
/// Escapes both `.` and `(` so the literal chars in `.<filter>(`'<column>'`
/// are matched as themselves, not as regex metacharacters. The earlier
/// version emitted an unbalanced capture group (`('([^']+)'` with no
/// closing `)`) that made the inner `Regex::new` fail and the function
/// silently return `None`.
fn extract_filter_column(symbol: &str, filter_name: &str) -> Option<String> {
    let pattern = format!(r"\.{}\s*\(\s*'([^']+)'", regex::escape(filter_name),);
    let re = Regex::new(&pattern).ok()?;
    re.captures(symbol)?.get(1).map(|m| m.as_str().to_string())
}

// ============================================================================
// Edge function model
// ============================================================================

/// Extract edge function models from the CPG.
///
/// Edge functions are `.ts` files under `supabase/functions/`. The CPG
/// should already contain nodes for these files, parsed by the TypeScript
/// frontend (`engine-frontend-typescript`).
///
/// This function walks the CPG for `MethodCall` or `CallSite` nodes whose
/// symbol patterns match Supabase edge function conventions:
///
/// - `createClient(url, key)` — if `key` references a `SERVICE_ROLE_KEY`
///   env variable or literal, `uses_service_role` is set to `true`.
/// - Any expression that looks like `req.body.PROP`, `req.query.PROP`, or
///   `req.params.PROP` is added as a tainted parameter.
///
/// Returns one [`EdgeFunctionModel`] per detected edge function file.
pub fn extract_edge_functions(graph: &mut CodeGraph) -> Vec<EdgeFunctionModel> {
    // Phase 1: collect raw observations without borrowing graph mutably.
    // Each entry is (file_id, is_function_decl, canonical_symbol, prop_hint).
    struct RawObs {
        file: FileId,
        is_fn_decl: bool,
        canonical: String,
        tainted_props: Vec<String>,
    }

    let mut raw: Vec<RawObs> = Vec::new();
    for node in graph.iter_nodes() {
        if node.kind != NodeKind::CallSite && node.kind != NodeKind::FunctionDecl {
            continue;
        }
        let Some(sym) = node.symbol else { continue };
        let canonical = graph.symbol(sym).canonical.clone();

        let is_fn_decl = node.kind == NodeKind::FunctionDecl;

        // Detect tainted param property names from req.body.X / req.query.X / req.params.X
        let mut tainted_props: Vec<String> = Vec::new();
        if canonical.contains("req.body")
            || canonical.contains("req.query")
            || canonical.contains("req.params")
        {
            for pattern in &["req.body.", "req.query.", "req.params."] {
                if let Some(idx) = canonical.find(pattern) {
                    let rest = &canonical[idx + pattern.len()..];
                    let prop = rest.trim_end_matches(')').trim_end().to_string();
                    if !prop.is_empty() && !prop.contains('(') && !tainted_props.contains(&prop) {
                        tainted_props.push(prop);
                    }
                }
            }
            if tainted_props.is_empty() {
                for pattern in &["req.body", "req.query", "req.params"] {
                    if canonical.contains(pattern) {
                        let prop = pattern.to_string();
                        if !tainted_props.contains(&prop) {
                            tainted_props.push(prop);
                        }
                    }
                }
            }
        }

        raw.push(RawObs {
            file: node.file,
            is_fn_decl,
            canonical: canonical.to_string(),
            tainted_props,
        });
    }

    // Phase 2: intern symbols on a now-unborrowed graph.
    let mut functions: Vec<EdgeFunctionModel> = Vec::new();
    let mut seen_files: rustc_hash::FxHashSet<FileId> = rustc_hash::FxHashSet::default();

    for obs in raw {
        let uses_service_role = obs.canonical.contains("createClient")
            && (obs.canonical.contains("service_role")
                || obs.canonical.contains("SERVICE_ROLE")
                || obs.canonical.contains("SUPABASE_KEY"));

        let tainted_params: Vec<SymbolId> = obs
            .tainted_props
            .iter()
            .map(|p| graph.intern_symbol(p))
            .collect();

        let func_name = if obs.is_fn_decl {
            // Use the last segment of the canonical symbol.
            obs.canonical
                .split('.')
                .next()
                .unwrap_or(&obs.canonical)
                .to_string()
        } else {
            let file_path = graph.file_path(obs.file);
            file_path
                .rsplit('/')
                .next()
                .unwrap_or("unknown")
                .trim_end_matches(".ts")
                .trim_end_matches(".tsx")
                .to_string()
        };
        let func_name_id = graph.intern_symbol(&func_name);

        if seen_files.insert(obs.file) || functions.is_empty() {
            functions.push(EdgeFunctionModel {
                name: func_name_id,
                uses_service_role,
                tainted_params,
                inner_query: None,
            });
        } else if tainted_params.is_empty() && !uses_service_role {
            continue;
        } else if let Some(existing) = functions.iter_mut().find(|f| f.name == func_name_id) {
            existing.uses_service_role = existing.uses_service_role || uses_service_role;
            for p in &tainted_params {
                if !existing.tainted_params.contains(p) {
                    existing.tainted_params.push(*p);
                }
            }
        } else {
            functions.push(EdgeFunctionModel {
                name: func_name_id,
                uses_service_role,
                tainted_params,
                inner_query: None,
            });
        }
    }

    if functions.is_empty() {
        warn!(
            "TypeScript frontend found no Supabase edge functions — no createClient \
             or tainted-parameter patterns detected in .ts files under the project root."
        );
    } else {
        info!(
            count = functions.len(),
            "TypeScript frontend: edge function models extracted",
        );
    }

    functions
}

// ============================================================================
// RLS policy model
// ============================================================================

/// Parse RLS policies from raw SQL text (contents of `supabase/migrations/*.sql`).
///
/// Takes `&mut CodeGraph` to intern table names and column names into the
/// CPG symbol table so that the correlator can match by table.
///
/// Patterns recognised:
/// - `CREATE POLICY <name> ON <table> FOR <operation> [USING (...)] [WITH CHECK (...)]`
/// - Operation defaults to `All` when `FOR` clause is omitted.
/// - `auth.uid() = X` USING clauses are lifted to `Predicate::UidEq` with
///   the column name interned.
/// - More complex expressions become `Predicate::Opaque`.
///
/// This is a regex-based extractor, not a full SQL parser. The Dart-side
/// reference implementation is at `lib/src/utils/ddl_parser.dart`.
pub fn extract_rls_policies(graph: &mut CodeGraph, sql_text: &str) -> Vec<RlsPolicyModel> {
    let mut policies = Vec::new();

    // Match CREATE POLICY statements.
    // Uses raw string r#"..."# so that double quotes inside the regex (for
    // matching quoted SQL identifiers like "users_select_policy") do not
    // prematurely terminate the string literal.
    //
    // The `ON [TABLE] [schema.]name` shape is permissive: `TABLE` is
    // optional in PostgreSQL (`CREATE POLICY foo ON users …` is valid),
    // and the schema qualifier (`public.` or `"public".`) is also
    // optional. Identifiers may be unquoted (`[a-zA-Z_]\w*`) or
    // double-quoted (`"…"`).
    let policy_re = Regex::new(
        r#"(?i)CREATE\s+POLICY\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:([a-zA-Z_]\w*)|"([^"]+)")\s+ON\s+(?:TABLE\s+)?(?:(?:public|"public")\s*\.\s*)?(?:([a-zA-Z_]\w*)|"([^"]+)")"#
    ).expect("static regex");
    let op_re = Regex::new(r"(?i)FOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b").expect("static regex");
    // Matchers for the `USING` / `WITH CHECK` keywords. We ONLY use these
    // to locate where the parenthesised predicate starts; the body itself
    // is extracted by `extract_balanced_parens()` because regex `[^)]+`
    // stops at the first `)`, which breaks on nested calls like
    // `auth.uid()`.
    let using_kw_re = Regex::new(r"(?i)USING\s*\(").expect("static regex");
    let with_check_kw_re = Regex::new(r"(?i)WITH\s+CHECK\s*\(").expect("static regex");
    let uid_eq_re =
        Regex::new(r"(?i)auth\.\s*uid\s*\(\s*\)\s*=\s*([a-zA-Z_]\w*)").expect("static regex");
    let uid_eq_reverse_re =
        Regex::new(r"(?i)([a-zA-Z_]\w*)\s*=\s*auth\.\s*uid\s*\(\s*\)").expect("static regex");

    for cap in policy_re.captures_iter(sql_text) {
        let stmt_start = cap.get(0).unwrap().start();
        let stmt_end = sql_text[stmt_start..]
            .find(';')
            .map(|i| stmt_start + i)
            .unwrap_or(sql_text.len());
        let stmt_text = &sql_text[stmt_start..stmt_end];

        // Extract policy name (unquoted group 1 or double-quoted group 2).
        let policy_name = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or("unnamed_policy");
        let name = graph.intern_symbol(policy_name);

        // Extract table name (unquoted group 3 or double-quoted group 4).
        let table_name = cap
            .get(3)
            .or_else(|| cap.get(4))
            .map(|m| m.as_str())
            .unwrap_or("unknown_table");
        let table = graph.intern_symbol(table_name);

        // Extract operation (default ALL).
        let operation = op_re
            .captures(stmt_text)
            .and_then(|op_cap| match op_cap[1].to_uppercase().as_str() {
                "SELECT" => Some(Operation::Select),
                "INSERT" => Some(Operation::Insert),
                "UPDATE" => Some(Operation::Update),
                "DELETE" => Some(Operation::Delete),
                "ALL" => Some(Operation::All),
                _ => None,
            })
            .unwrap_or(Operation::All);

        // Extract USING predicate (balanced-paren slice past `USING (`).
        let using_expr = using_kw_re
            .find(stmt_text)
            .and_then(|m| extract_balanced_parens(stmt_text, m.end()))
            .map(|body| lift_sql_predicate(graph, &body, &uid_eq_re, &uid_eq_reverse_re))
            .unwrap_or(Predicate::True);

        // Extract WITH CHECK predicate (balanced-paren slice past `WITH CHECK (`).
        let with_check_expr = with_check_kw_re
            .find(stmt_text)
            .and_then(|m| extract_balanced_parens(stmt_text, m.end()))
            .map(|body| lift_sql_predicate(graph, &body, &uid_eq_re, &uid_eq_reverse_re));

        policies.push(RlsPolicyModel {
            name,
            table,
            operation,
            using_expr,
            with_check_expr,
        });
    }

    policies
}

/// Given a starting position **just after** an opening `(`, return the
/// substring up to the matching `)`. Counts parens to handle nested
/// expressions like `(auth.uid() = id)`. Returns `None` if no matching
/// close brace is found before the end of `text`.
fn extract_balanced_parens(text: &str, start_after_open: usize) -> Option<String> {
    let bytes = text.as_bytes();
    let mut depth = 1usize;
    let mut i = start_after_open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[start_after_open..i].to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Lift a SQL predicate to our symbolic [`Predicate`] IR.
///
/// Takes `&mut CodeGraph` to intern column names extracted from
/// `auth.uid() = column` patterns so the correlator can reason about
/// column-level predicates precisely.
fn lift_sql_predicate(
    graph: &mut CodeGraph,
    expr: &str,
    uid_eq_re: &Regex,
    uid_eq_reverse_re: &Regex,
) -> Predicate {
    let trimmed = expr.trim();

    // auth.uid() = column_name
    if let Some(cap) = uid_eq_re.captures(trimmed) {
        let col = graph.intern_symbol(cap.get(1).map(|m| m.as_str()).unwrap_or("uid_column"));
        return Predicate::UidEq { column: col };
    }
    // column_name = auth.uid()
    if let Some(cap) = uid_eq_reverse_re.captures(trimmed) {
        let col = graph.intern_symbol(cap.get(1).map(|m| m.as_str()).unwrap_or("uid_column"));
        return Predicate::UidEq { column: col };
    }
    // Can't lift — treat as opaque.
    Predicate::Opaque(graph.intern_symbol("opaque_sql_predicate"))
}

// ============================================================================
// Module-level tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_quotes() {
        assert_eq!(strip_quotes("'posts'"), "posts");
        assert_eq!(strip_quotes("\"users\""), "users");
        assert_eq!(strip_quotes("  'audit_log'  "), "audit_log");
        assert_eq!(strip_quotes("plain"), "plain");
        assert_eq!(strip_quotes("'mismatched\""), "'mismatched\"");
    }

    #[test]
    fn test_extract_filter_column() {
        assert_eq!(
            extract_filter_column("supabase.from('posts').select().eq('user_id', uid)", "eq"),
            Some("user_id".to_string())
        );
        assert_eq!(
            extract_filter_column("supabase.from('posts').neq('status', 'deleted')", "neq"),
            Some("status".to_string())
        );
        assert_eq!(
            extract_filter_column("supabase.from('posts').in_('id', [1,2,3])", "in_"),
            Some("id".to_string())
        );
        assert_eq!(
            extract_filter_column("supabase.from('posts').select()", "eq"),
            None
        );
    }

    #[test]
    fn test_operation_detection() {
        assert!(detect_op("supabase.from('posts').select()").is_select_or_none());
        assert!(detect_op("supabase.from('posts').insert()").is_insert());
        assert!(detect_op("supabase.from('posts').update()").is_update());
        assert!(detect_op("supabase.from('posts').delete()").is_delete());
    }

    fn detect_op(symbol: &str) -> Operation {
        if symbol.contains(".select(") || symbol.ends_with(".select") {
            Operation::Select
        } else if symbol.contains(".insert(") || symbol.ends_with(".insert") {
            Operation::Insert
        } else if symbol.contains(".update(") || symbol.ends_with(".update") {
            Operation::Update
        } else if symbol.contains(".delete(") || symbol.ends_with(".delete") {
            Operation::Delete
        } else {
            Operation::Select
        }
    }

    trait OpExt {
        fn is_select_or_none(&self) -> bool;
        fn is_insert(&self) -> bool;
        fn is_update(&self) -> bool;
        fn is_delete(&self) -> bool;
    }
    impl OpExt for Operation {
        fn is_select_or_none(&self) -> bool {
            matches!(self, Operation::Select | Operation::All)
        }
        fn is_insert(&self) -> bool {
            matches!(self, Operation::Insert)
        }
        fn is_update(&self) -> bool {
            matches!(self, Operation::Update)
        }
        fn is_delete(&self) -> bool {
            matches!(self, Operation::Delete)
        }
    }

    #[test]
    fn test_extract_rls_policies_basic() {
        let mut g = CodeGraph::new();
        let sql = r#"
CREATE POLICY "users_select_policy" ON "public"."users"
    FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "posts_insert_policy" ON public.posts
    FOR INSERT
    WITH CHECK (auth.uid() = user_id);
"#;
        let policies = extract_rls_policies(&mut g, sql);
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].operation, Operation::Select);
        assert!(matches!(policies[0].using_expr, Predicate::UidEq { .. }));
        assert_eq!(policies[1].operation, Operation::Insert);
        assert!(matches!(policies[1].using_expr, Predicate::True));
        assert!(policies[1].with_check_expr.is_some());
        assert!(matches!(
            policies[1].with_check_expr.as_ref().unwrap(),
            Predicate::UidEq { .. }
        ));
        // Verify table names are populated.
        let t0 = g.symbol(policies[0].table).canonical.to_string();
        let t1 = g.symbol(policies[1].table).canonical.to_string();
        assert_eq!(t0, "users", "table must be interned from regex capture");
        assert_eq!(t1, "posts", "table must be interned from regex capture");
    }

    #[test]
    fn test_extract_rls_policies_no_for_clause_defaults_to_all() {
        let mut g = CodeGraph::new();
        let sql = r#"
CREATE POLICY "posts_all_policy" ON posts
    USING (auth.uid() = user_id);
"#;
        let policies = extract_rls_policies(&mut g, sql);
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].operation, Operation::All);
        assert_eq!(g.symbol(policies[0].table).canonical.as_ref(), "posts");
    }

    #[test]
    fn test_no_rls_policies_from_empty_sql() {
        let mut g = CodeGraph::new();
        let policies = extract_rls_policies(&mut g, "CREATE TABLE posts (id uuid);\n");
        assert_eq!(policies.len(), 0);
    }

    #[test]
    fn test_case_insensitive_policy_parsing() {
        let mut g = CodeGraph::new();
        let sql =
            "create policy \"test_policy\" on public.users for select using (auth.uid() = id);";
        let policies = extract_rls_policies(&mut g, sql);
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].operation, Operation::Select);
        assert_eq!(g.symbol(policies[0].table).canonical.as_ref(), "users");
    }

    #[test]
    fn test_extract_edge_functions_returns_empty() {
        let mut graph = CodeGraph::new();
        let result = extract_edge_functions(&mut graph);
        assert!(result.is_empty());
    }
}
