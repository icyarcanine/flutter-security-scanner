//! SQL parser for Supabase RLS policy DDL statements.
//!
//! Parses `CREATE POLICY name ON table FOR operation USING (expr) WITH CHECK (expr)`
//! into a structured AST. Handles nested parentheses, compound AND/OR predicates,
//! and auth.uid() function calls.

use regex::Regex;

use super::model::*;

/// SQL parser for RLS policy DDL.
pub struct SqlParser<'a> {
    source: &'a str,
}

impl<'a> SqlParser<'a> {
    pub fn new(source: &'a str) -> Self {
        Self { source }
    }

    /// Parse all CREATE POLICY statements from the source.
    pub fn parse_all(&self) -> Vec<RlsPolicyAst> {
        let mut policies = Vec::new();
        // Handle both quoted ("policy name with spaces") and unquoted (simple_identifier) identifiers.
        let re = Regex::new(
            r#"(?is)CREATE\s+POLICY\s+(?:"([^"]*)"|(\w+))\s+ON\s+(?:"([^"]*)"|(\w+))\s*(?:FOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE))?\s*(?:TO\s+((?:"[^"]*"|\w+)(?:\s*,\s*(?:"[^"]*"|\w+))*))?\s*(?:USING\s*\((.+?)\)\s*)?(?:WITH\s+CHECK\s*\((.+?)\)\s*)?;"#
        ).unwrap();

        for cap in re.captures_iter(self.source) {
            // If quoted (group 1), re-wrap with quotes to match test expectations.
            // If unquoted (group 2), use as-is.
            let name = match cap.get(1) {
                Some(m) => format!("\"{}\"", m.as_str()),
                None => cap.get(2).map(|m| m.as_str()).unwrap_or("").to_string(),
            };
            let table = cap
                .get(3)
                .map(|m| m.as_str())
                .or_else(|| cap.get(4).map(|m| m.as_str()))
                .unwrap_or("")
                .to_string();
            let operation = match cap.get(5) {
                Some(m) => match m.as_str().to_uppercase().as_str() {
                    "ALL" => SqlOperation::All,
                    "SELECT" => SqlOperation::Select,
                    "INSERT" => SqlOperation::Insert,
                    "UPDATE" => SqlOperation::Update,
                    "DELETE" => SqlOperation::Delete,
                    _ => SqlOperation::All,
                },
                None => SqlOperation::All,
            };
            // Capture groups:
            // 1=quoted_name, 2=unquoted_name, 3=quoted_table, 4=unquoted_table,
            // 5=operation, 6=roles, 7=using_expr, 8=check_expr
            let roles = match cap.get(6) {
                Some(m) => m
                    .as_str()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                None => vec!["authenticated".to_string()],
            };
            let using_expr = cap.get(7).map(|m| self.parse_predicate(m.as_str()));
            let check_expr = cap.get(8).map(|m| self.parse_predicate(m.as_str()));
            let raw = cap[0].to_string();

            policies.push(RlsPolicyAst {
                name,
                table,
                operation,
                using_expr,
                check_expr,
                roles,
                raw,
            });
        }

        policies
    }

    /// Parse a predicate expression (e.g. `column = auth.uid() AND other = true`).
    fn parse_predicate(&self, expr: &str) -> SqlExpr {
        let expr = expr.trim();

        // Handle empty/null expressions
        if expr.is_empty() || expr == "true" {
            return SqlExpr::BooleanLiteral(true);
        }
        if expr == "false" {
            return SqlExpr::BooleanLiteral(false);
        }

        // First, split on OR at the top level (outside parens)
        let or_parts = self.split_top_level(expr, "OR");
        if or_parts.len() > 1 {
            let clauses = or_parts
                .into_iter()
                .map(|p| self.parse_and_chain(p.trim()))
                .collect();
            return SqlExpr::Compound {
                op: LogicalOp::Or,
                clauses,
            };
        }

        // Then split on AND
        let and_parts = self.split_top_level(expr, "AND");
        if and_parts.len() > 1 {
            let clauses = and_parts
                .into_iter()
                .map(|p| Self::parse_comparison(p.trim()))
                .collect();
            return SqlExpr::Compound {
                op: LogicalOp::And,
                clauses,
            };
        }

        // Single expression
        Self::parse_comparison(expr)
    }

    /// Split a string by a keyword, respecting parentheses nesting.
    fn split_top_level<'s>(&self, s: &'s str, keyword: &str) -> Vec<&'s str> {
        let mut depth: i32 = 0;
        let mut parts = Vec::new();
        let mut start = 0;
        let keyword_upper = keyword.to_uppercase();

        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ if depth == 0 => {
                    // Check if this position matches the keyword
                    if i + keyword.len() <= chars.len() {
                        let slice: String = chars[i..i + keyword.len()].iter().collect();
                        if slice.to_uppercase() == keyword_upper {
                            let part = s[start..i].trim();
                            if !part.is_empty() {
                                parts.push(part);
                            }
                            i += keyword.len();
                            start = i;
                            continue;
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
        // Remaining part
        if start < chars.len() {
            let part = s[start..].trim();
            if !part.is_empty() {
                parts.push(part);
            }
        }

        parts
    }

    /// Parse AND-chained expressions.
    fn parse_and_chain(&self, expr: &str) -> SqlExpr {
        let parts = self.split_top_level(expr, "AND");
        if parts.len() > 1 {
            let clauses = parts
                .into_iter()
                .map(|p| Self::parse_comparison(p.trim()))
                .collect();
            return SqlExpr::Compound {
                op: LogicalOp::And,
                clauses,
            };
        }
        Self::parse_comparison(expr)
    }

    /// Parse a single comparison expression.
    fn parse_comparison(expr: &str) -> SqlExpr {
        let expr = expr.trim();

        // Handle NOT
        if expr.to_uppercase().starts_with("NOT ") {
            let inner = &expr[4..];
            return SqlExpr::UnaryOp {
                op: UnaryOp::Not,
                expr: Box::new(Self::parse_comparison(inner.trim())),
            };
        }

        // Handle IS NOT NULL
        if let Some(pos) = expr.to_uppercase().find(" IS NOT NULL") {
            let left = &expr[..pos];
            return SqlExpr::UnaryOp {
                op: UnaryOp::IsNotNull,
                expr: Box::new(Self::parse_comparison(left.trim())),
            };
        }

        // Handle IS NULL
        if let Some(pos) = expr.to_uppercase().find(" IS NULL") {
            let left = &expr[..pos];
            return SqlExpr::UnaryOp {
                op: UnaryOp::IsNull,
                expr: Box::new(Self::parse_comparison(left.trim())),
            };
        }

        // Handle IN/NOT IN
        let in_re = Regex::new(r"(?i)^(.+?)\s+(NOT\s+)?IN\s*\((.+)\)$").unwrap();
        if let Some(cap) = in_re.captures(expr) {
            let left = Self::parse_value(cap[1].trim());
            let op = if cap.get(2).is_some() {
                BinOp::NotIn
            } else {
                BinOp::In
            };
            let right = SqlExpr::Opaque(cap[3].to_string());
            return SqlExpr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }

        // Handle LIKE, ILIKE
        let like_re = Regex::new(r"(?i)^(.+?)\s+(NOT\s+)?(LIKE|ILIKE)\s+(.+)$").unwrap();
        if let Some(cap) = like_re.captures(expr) {
            let left = Self::parse_value(cap[1].trim());
            let op = if cap.get(2).is_some() {
                BinOp::NotIn // approximate
            } else {
                match cap[3].to_uppercase().as_str() {
                    "LIKE" => BinOp::Like,
                    "ILIKE" => BinOp::ILike,
                    _ => BinOp::Like,
                }
            };
            let right = Self::parse_value(cap[4].trim());
            return SqlExpr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }

        // Handle comparison operators: =, !=, <>, <, <=, >, >=
        let cmp_re = Regex::new(r"^(.+?)\s*(!==?|<>|<=|>=|<|>|==|=)\s*(.+)$").unwrap();
        if let Some(cap) = cmp_re.captures(expr) {
            let op = match cap[2].trim() {
                "=" | "==" => BinOp::Eq,
                "!=" | "!==" | "<>" => BinOp::Neq,
                "<" => BinOp::Lt,
                "<=" => BinOp::Lte,
                ">" => BinOp::Gt,
                ">=" => BinOp::Gte,
                _ => BinOp::Eq,
            };
            let left = Self::parse_value(cap[1].trim());
            let right = Self::parse_value(cap[3].trim());
            return SqlExpr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }

        // Handle IS (boolean comparison)
        let is_re =
            Regex::new(r"(?i)^(.+?)\s+IS\s+(NOT\s+)?(TRUE|FALSE|NULL|UNKNOWN)\s*$").unwrap();
        if let Some(cap) = is_re.captures(expr) {
            let left = Self::parse_value(cap[1].trim());
            let op = if cap.get(2).is_some() {
                BinOp::IsNot
            } else {
                BinOp::Is
            };
            let right = SqlExpr::BooleanLiteral(cap[3].to_uppercase() == "TRUE");
            return SqlExpr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }

        // Fall through: try to parse as a value expression
        Self::parse_value(expr)
    }

    /// Parse a value expression (column reference, function call, literal).
    fn parse_value(expr: &str) -> SqlExpr {
        let expr = expr.trim();

        // Empty
        if expr.is_empty() {
            return SqlExpr::Null;
        }

        // String literal
        if (expr.starts_with('\'') && expr.ends_with('\''))
            || (expr.starts_with('"') && expr.ends_with('"'))
        {
            let inner = &expr[1..expr.len() - 1];
            return SqlExpr::StringLiteral(inner.to_string());
        }

        // Boolean literals
        match expr.to_uppercase().as_str() {
            "TRUE" => return SqlExpr::BooleanLiteral(true),
            "FALSE" => return SqlExpr::BooleanLiteral(false),
            "NULL" => return SqlExpr::Null,
            _ => {}
        }

        // Numeric literal
        let num_re = Regex::new(r"^\d+(\.\d+)?$").unwrap();
        if num_re.is_match(expr) {
            return SqlExpr::NumberLiteral(expr.to_string());
        }

        // Function call: name(arg, ...)
        let fn_re = Regex::new(r"^(\w+(?:\.\w+)*)\(([^()]*)\)$").unwrap();
        if let Some(cap) = fn_re.captures(expr) {
            let name = cap[1].to_string();
            let args_str = cap[2].trim();
            let args = if args_str.is_empty() {
                vec![]
            } else {
                args_str
                    .split(',')
                    .map(|s| Self::parse_value(s.trim()))
                    .collect()
            };
            return SqlExpr::FunctionCall { name, args };
        }

        // Subquery (starts with SELECT)
        if expr.to_uppercase().starts_with("SELECT ") {
            return SqlExpr::Subquery(expr.to_string());
        }

        // Column reference
        let parts: Vec<String> = expr.split('.').map(|s| s.trim().to_string()).collect();
        SqlExpr::ColumnRef { parts }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_policy() {
        let sql = "CREATE POLICY \"Users can view own profile\" ON profiles FOR SELECT USING (id = auth.uid());";
        let parser = SqlParser::new(sql);
        let policies = parser.parse_all();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].name, "\"Users can view own profile\"");
        assert_eq!(policies[0].table, "profiles");
        assert_eq!(policies[0].operation, SqlOperation::Select);
        assert!(policies[0].using_expr.is_some());
    }

    #[test]
    fn test_policy_with_and() {
        let sql = "CREATE POLICY \"tenant_isolation\" ON documents FOR ALL USING (tenant_id = auth.jwt()->'tenant_id' AND deleted_at IS NULL);";
        let parser = SqlParser::new(sql);
        let policies = parser.parse_all();
        assert_eq!(policies.len(), 1);
        let expr = policies[0].using_expr.as_ref().unwrap();
        match expr {
            SqlExpr::Compound { op, clauses } => {
                assert_eq!(*op, LogicalOp::And);
                assert_eq!(clauses.len(), 2);
            }
            _ => panic!("Expected Compound expression, got {:?}", expr),
        }
    }

    #[test]
    fn test_policy_with_check() {
        let sql = "CREATE POLICY \"insert_own\" ON comments FOR INSERT WITH CHECK (author_id = auth.uid());";
        let parser = SqlParser::new(sql);
        let policies = parser.parse_all();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].operation, SqlOperation::Insert);
        assert!(policies[0].check_expr.is_some());
        assert!(policies[0].using_expr.is_none());
    }

    #[test]
    fn test_function_call() {
        let sql = "CREATE POLICY \"owner_access\" ON files FOR ALL USING (auth.uid() = owner_id);";
        let parser = SqlParser::new(sql);
        let policies = parser.parse_all();
        let expr = policies[0].using_expr.as_ref().unwrap();
        match expr {
            SqlExpr::BinaryOp { left, op, right: _ } => {
                assert_eq!(*op, BinOp::Eq);
                match left.as_ref() {
                    SqlExpr::FunctionCall { name, args } => {
                        assert_eq!(name, "auth.uid");
                        assert!(args.is_empty());
                    }
                    _ => panic!("Expected function call"),
                }
            }
            _ => panic!("Expected BinaryOp"),
        }
    }

    #[test]
    fn test_multiple_policies() {
        let sql = "CREATE POLICY \"select_policy\" ON test FOR SELECT USING (true);\nCREATE POLICY \"insert_policy\" ON test FOR INSERT WITH CHECK (true);";
        let parser = SqlParser::new(sql);
        let policies = parser.parse_all();
        assert_eq!(policies.len(), 2);
    }

    #[test]
    fn test_roles() {
        let sql =
            "CREATE POLICY \"admin_only\" ON secrets TO authenticated, service_role USING (true);";
        let parser = SqlParser::new(sql);
        let policies = parser.parse_all();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].roles, vec!["authenticated", "service_role"]);
    }
}
