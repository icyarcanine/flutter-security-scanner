//! SQL AST models for RLS policy statements.

use std::fmt;

/// A parsed RLS policy statement.
#[derive(Clone, Debug, PartialEq)]
pub struct RlsPolicyAst {
    /// Policy name (from CREATE POLICY `name` ON ...)
    pub name: String,
    /// Target table
    pub table: String,
    /// SQL operation the policy applies to
    pub operation: SqlOperation,
    /// USING clause predicate (for SELECT/UPDATE/DELETE)
    pub using_expr: Option<SqlExpr>,
    /// WITH CHECK clause predicate (for INSERT/UPDATE)
    pub check_expr: Option<SqlExpr>,
    /// Role specification (PUBLIC, authenticated, etc.)
    pub roles: Vec<String>,
    /// The raw SQL text of this policy
    pub raw: String,
}

/// SQL operations that RLS policies can apply to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SqlOperation {
    All,
    Select,
    Insert,
    Update,
    Delete,
}

impl fmt::Display for SqlOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SqlOperation::All => write!(f, "ALL"),
            SqlOperation::Select => write!(f, "SELECT"),
            SqlOperation::Insert => write!(f, "INSERT"),
            SqlOperation::Update => write!(f, "UPDATE"),
            SqlOperation::Delete => write!(f, "DELETE"),
        }
    }
}

/// A SQL expression in a policy predicate.
#[derive(Clone, Debug, PartialEq)]
pub enum SqlExpr {
    /// Binary comparison: `column = value`
    BinaryOp {
        left: Box<SqlExpr>,
        op: BinOp,
        right: Box<SqlExpr>,
    },
    /// Unary expression: `NOT expr`
    UnaryOp { op: UnaryOp, expr: Box<SqlExpr> },
    /// Function call: `auth.uid()`
    FunctionCall { name: String, args: Vec<SqlExpr> },
    /// Column reference: `column_name` or `table.column`
    ColumnRef { parts: Vec<String> },
    /// String literal
    StringLiteral(String),
    /// Numeric literal
    NumberLiteral(String),
    /// Boolean literal
    BooleanLiteral(bool),
    /// NULL literal
    Null,
    /// A compound expression (AND/OR chain)
    Compound {
        op: LogicalOp,
        clauses: Vec<SqlExpr>,
    },
    /// Subquery: `(SELECT ...)`
    Subquery(String),
    /// Anything we couldn't parse
    Opaque(String),
}

/// Binary operators used in SQL predicates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BinOp {
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    NotIn,
    Like,
    ILike,
    Is,
    IsNot,
}

/// Unary operators.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UnaryOp {
    Not,
    IsNull,
    IsNotNull,
}

/// Logical operators for compound expressions.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LogicalOp {
    And,
    Or,
}
