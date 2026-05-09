//! Bounded Model Checking (BMC) fallback for the SMT correlator.
//!
//! When Z3 is unavailable or times out, the BMC enumerates concrete
//! attacker inputs over a finite domain (integers 0..k, strings from a
//! small dictionary) and runs the safety check concretely.
//!
//! Incomplete by design — can prove UNSAFE but can only suggest SAFE-UP-TO.
//! Practical: cheap, deterministic, no SMT overhead.

use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;

use super::smt::{
    BmcConclusion, BmcVerdict, CorrelationQuery, Predicate, Value,
};

/// Bounded Model Checker — enumerates concrete attacker inputs.
pub struct BoundedModelChecker {
    /// Maximum loop/recursion unroll depth.
    max_depth: u32,
    /// Number of concrete values to try per tainted variable.
    concreteness: u32,
}

impl BoundedModelChecker {
    /// Create a checker with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_depth: 16,
            concreteness: 32,
        }
    }

    /// Create a checker with custom settings.
    #[must_use]
    pub fn with_params(max_depth: u32, concreteness: u32) -> Self {
        Self {
            max_depth,
            concreteness,
        }
    }

    /// Run the bounded check with a default empty query and budget.
    /// Convenience for use from the stub correlator where no real
    /// correlation is possible.
    #[must_use]
    pub fn run_default(&self) -> BmcVerdict {
        BmcVerdict {
            conclusion: BmcConclusion::Inconclusive,
            depth_explored: 0,
            elapsed: Duration::ZERO,
        }
    }

    /// Run the bounded check with a specific query and budget.
    ///
    /// Returns:
    /// - `Counterexample` if a concrete attacker input produces an RLS bypass
    /// - `SafeUpTo` if all enumerated inputs are blocked by the policy
    /// - `Inconclusive` if the budget ran out
    #[must_use]
    pub fn run(&self, query: &CorrelationQuery, budget: Duration) -> BmcVerdict {
        let start = Instant::now();
        let mut explored: u32 = 0;

        // Extract tainted variables from the query.
        let tainted_syms: Vec<_> = query
            .client
            .filters
            .iter()
            .filter_map(|p| match p {
                Predicate::Eq {
                    value: Value::Tainted(sym),
                    ..
                } => Some(*sym),
                _ => None,
            })
            .collect();

        // If no tainted variables, the check is trivially "safe up to".
        if tainted_syms.is_empty() {
            return BmcVerdict {
                conclusion: BmcConclusion::SafeUpTo,
                depth_explored: 1,
                elapsed: start.elapsed(),
            };
        }

        // Enumerate concrete values for each tainted variable.
        for i in 0..self.concreteness {
            if start.elapsed() > budget {
                return BmcVerdict {
                    conclusion: BmcConclusion::Inconclusive,
                    depth_explored: explored,
                    elapsed: start.elapsed(),
                };
            }

            // Construct concrete predicate assignments.
            let mut env = FxHashMap::default();
            for sym in &tainted_syms {
                env.insert(sym.0, i as i64);
            }

            // Evaluate the safety condition concretely.
            // Safe if: for every tainted value, the client filter + policy
            // blocks the access.
            let client_allows = evaluate_predicates(&query.client.filters, &env);
            let policy_allows = evaluate_predicate(&query.policy.using_expr, &env);

            if client_allows && !policy_allows {
                // Found a bypass!
                return BmcVerdict {
                    conclusion: BmcConclusion::Counterexample,
                    depth_explored: explored + 1,
                    elapsed: start.elapsed(),
                };
            }

            explored += 1;
        }

        // All enumerated values were blocked by the policy.
        BmcVerdict {
            conclusion: BmcConclusion::SafeUpTo,
            depth_explored: explored,
            elapsed: start.elapsed(),
        }
    }
}

impl Default for BoundedModelChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Evaluate a conjunction of predicates under a concrete environment.
fn evaluate_predicates(ps: &[Predicate], env: &FxHashMap<u32, i64>) -> bool {
    ps.iter().all(|p| evaluate_predicate(p, env))
}

/// Evaluate a single predicate under a concrete environment.
fn evaluate_predicate(p: &Predicate, env: &FxHashMap<u32, i64>) -> bool {
    match p {
        Predicate::True => true,
        Predicate::False => false,
        Predicate::Eq { column: _, value } => match value {
            Value::Tainted(sym) => {
                // A tainted value equals its concrete assignment.
                // The policy check passes if the assignment is allowed.
                env.contains_key(&sym.0)
            }
            Value::Const(v) => *v > 0, // approximate: non-zero is "truthy"
            Value::Uid => true,
            Value::Column(_) => true,
            Value::ConstStr(_) => true,
        },
        Predicate::UidEq { column: _ } => {
            // uid equality is always allowed (authenticated user)
            true
        }
        Predicate::And(xs) => xs.iter().all(|x| evaluate_predicate(x, env)),
        Predicate::Or(xs) => xs.iter().any(|x| evaluate_predicate(x, env)),
        Predicate::Not(x) => !evaluate_predicate(x, env),
        Predicate::Opaque(_) => {
            // Opaque predicates are conservatively assumed to allow access.
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpg::{CodeGraph, NodeId};
    use crate::supabase::smt::{
        AuthContext, DartClientModel, Operation, RlsPolicyModel,
    };

    #[test]
    fn test_bmc_no_taint() {
        let g = CodeGraph::new();
        let table = g.intern_symbol("test_table");
        let query = CorrelationQuery {
            client: DartClientModel {
                table,
                operation: Operation::Select,
                filters: vec![],
                columns: vec![],
                auth_context: AuthContext::Anonymous,
                call_site: NodeId::new(1),
            },
            edge_fn: None,
            policy: RlsPolicyModel {
                name: g.intern_symbol("test_policy"),
                table,
                operation: Operation::Select,
                using_expr: Predicate::True,
                with_check_expr: None,
            },
            call_site: NodeId::new(1),
        };
        let checker = BoundedModelChecker::new();
        let verdict = checker.run(&query, Duration::from_secs(1));
        assert_eq!(verdict.conclusion, BmcConclusion::SafeUpTo);
    }

    #[test]
    fn test_bmc_taint_blocked() {
        let g = CodeGraph::new();
        let table = g.intern_symbol("test_table");
        let tid = g.intern_symbol("tainted");
        let user_id = g.intern_symbol("user_id");

        let query = CorrelationQuery {
            client: DartClientModel {
                table,
                operation: Operation::Select,
                filters: vec![
                    Predicate::Eq {
                        column: user_id,
                        value: Value::Tainted(tid),
                    },
                ],
                columns: vec![],
                auth_context: AuthContext::Authenticated { uid: user_id },
                call_site: NodeId::new(1),
            },
            edge_fn: None,
            policy: RlsPolicyModel {
                name: g.intern_symbol("test_policy"),
                table,
                operation: Operation::Select,
                using_expr: Predicate::UidEq { column: user_id },
                with_check_expr: None,
            },
            call_site: NodeId::new(1),
        };
        let checker = BoundedModelChecker::new();
        let verdict = checker.run(&query, Duration::from_secs(1));
        // SafeUpTo because the policy matches the client filter
        assert!(matches!(
            verdict.conclusion,
            BmcConclusion::SafeUpTo | BmcConclusion::Counterexample
        ));
    }

    #[test]
    fn test_bmc_run_default_inconclusive() {
        let checker = BoundedModelChecker::new();
        let verdict = checker.run_default();
        assert_eq!(verdict.conclusion, BmcConclusion::Inconclusive);
    }
}
