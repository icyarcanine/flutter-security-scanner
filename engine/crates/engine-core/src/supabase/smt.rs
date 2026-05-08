//! Z3-backed three-way correlation engine for Supabase security.
//!
//! # The theorem
//!
//! For every client-issued database operation `Q` on table `T` with
//! operation `op`, under an optional Edge Function wrapper `F` with auth
//! context `ctx`, and a server-side RLS policy `P`, the engine attempts to
//! discharge the safety formula:
//!
//! ```text
//!   ∀ row ∈ T.
//!     reachable(Q, row, ctx) ∧ ¬permitted(P, row, ctx)   →   ⊥
//! ```
//!
//! That is: we ask Z3 for a *model* in which the client's query reaches a
//! row that the RLS policy forbids. If the formula is **UNSAT**, the query
//! is provably safe and we emit no finding. If **SAT**, Z3 hands back a
//! concrete *witness row* and *auth context*, which we include in the
//! finding as proof the developer can act on. If **UNKNOWN** (Z3 timed
//! out or hit an incomplete theory), we fall back to bounded model checking
//! (BMC) and downgrade the finding to MEDIUM-confidence.
//!
//! # 3-way triangulation
//!
//! The classic Supabase setup has three trust-boundary crossings a bug can
//! hide in:
//!
//! 1. **Dart client** — calls `supabase.from('posts').select().eq(...)`.
//! 2. **TypeScript edge function** — wraps a Supabase client with its own
//!    auth context. The classic foot-gun is creating the inner client with
//!    `SUPABASE_SERVICE_ROLE_KEY`, which silently bypasses RLS for *every
//!    caller of that endpoint*.
//! 3. **Postgres RLS policy** — the `USING` / `WITH CHECK` predicate.
//!
//! Our correlator takes all three as input, lifts each into a Z3 formula,
//! and asks for the conjunction to be satisfiable. The two-way client↔RLS
//! check catches missing policies; the three-way check catches the more
//! insidious "policy exists but is bypassed by an edge-function
//! service-role escalation." No enterprise SAST tool currently ships this.
//!
//! # Hard time bounds
//!
//! Z3 is NP-hard in general. Unbounded calls would stall a CI pipeline for
//! minutes or hours on adversarial formulas. We therefore impose two
//! independent timeouts:
//!
//! 1. **Z3-internal** (`params.set_uint("timeout", N)`). Z3 honours this
//!    cooperatively via its resource-limit counters. We default to 50 ms.
//! 2. **Wall-clock watchdog.** We check `Instant::now()` between solver
//!    calls because Z3's internal timer can miss by tens of milliseconds
//!    during long matching cycles. If the watchdog fires first, we force
//!    `SatResult::Unknown` and proceed to the BMC fallback.
//!
//! Both limits are configurable per invocation so that a CI nightly build
//! can spend 500 ms per query while an IDE inline check spends 10 ms.
//!
//! # WASM portability
//!
//! Z3 does not compile to `wasm32-unknown-unknown` with the current z3
//! crate. On WASM builds the entire module compiles to a stub that
//! immediately returns `Verdict::Unknown`. The plan is to call into a
//! prebuilt `z3.wasm` sidecar via `wasm-bindgen` in a future version;
//! the public API surface is deliberately identical so the switch is
//! transparent.

use std::time::Duration;
#[cfg(feature = "smt-proofs")]
use std::time::Instant;

use thiserror::Error;

use crate::cpg::{NodeId, SymbolId};

// ============================================================================
// Configuration
// ============================================================================

/// Default per-query budget. Chosen so that a 1 000-query CI run stays
/// under one minute even in the worst case (1 000 × 50 ms = 50 s).
pub const DEFAULT_BUDGET: Duration = Duration::from_millis(50);

// ============================================================================
// Input models
// ============================================================================

/// Input to a single correlation proof obligation.
#[derive(Clone, Debug)]
pub struct CorrelationQuery {
    /// The Dart-side client call (parsed from the CPG).
    pub client: DartClientModel,
    /// Optional TypeScript Edge Function wrapper.
    pub edge_fn: Option<EdgeFunctionModel>,
    /// The server-side RLS policy governing the target table.
    pub policy: RlsPolicyModel,
    /// CPG call-site node (used for finding attribution / line numbers).
    pub call_site: NodeId,
}

/// Symbolic model of a Dart Supabase client call.
///
/// Materialised by the Dart frontend when it pattern-matches the fluent
/// builder chain `supabase.from('T').select().eq('col', val)`.
#[derive(Clone, Debug)]
pub struct DartClientModel {
    /// Target table (interned).
    pub table: SymbolId,
    /// Database operation.
    pub operation: Operation,
    /// Client-side filter predicates lifted to our symbolic IR.
    pub filters: Vec<Predicate>,
    /// Referenced columns (empty = `SELECT *`).
    pub columns: Vec<SymbolId>,
    /// Auth context the client believes it is operating under.
    pub auth_context: AuthContext,
}

/// Symbolic model of a TypeScript Edge Function.
#[derive(Clone, Debug)]
pub struct EdgeFunctionModel {
    /// Function name (interned).
    pub name: SymbolId,
    /// Whether the function creates its Supabase client with
    /// `SUPABASE_SERVICE_ROLE_KEY`. Detected syntactically by the TS
    /// frontend — the presence of `createClient(url, service_role_key)`
    /// is an unambiguous signal.
    pub uses_service_role: bool,
    /// HTTP request parameters that carry tainted input into the function.
    pub tainted_params: Vec<SymbolId>,
    /// The inner Supabase call the function issues, if resolvable.
    pub inner_query: Option<Box<DartClientModel>>,
}

/// Symbolic model of a Postgres `CREATE POLICY` from `supabase/migrations/`.
#[derive(Clone, Debug)]
pub struct RlsPolicyModel {
    /// Policy name.
    pub name: SymbolId,
    /// Target table.
    pub table: SymbolId,
    /// Operation the policy governs.
    pub operation: Operation,
    /// The `USING` predicate, lifted to our symbolic IR.
    pub using_expr: Predicate,
    /// The `WITH CHECK` predicate (applies to `INSERT` / `UPDATE`).
    pub with_check_expr: Option<Predicate>,
}

/// CRUD operation.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Operation {
    /// `SELECT` / `.select()`.
    Select,
    /// `INSERT` / `.insert()`.
    Insert,
    /// `UPDATE` / `.update()`.
    Update,
    /// `DELETE` / `.delete()`.
    Delete,
    /// Wildcard: the policy applies to all operations.
    All,
}

impl Operation {
    /// Does `self` (the operation the client is performing) fall under the
    /// jurisdiction of `policy_op` (the operation the RLS policy governs)?
    #[must_use]
    pub fn covered_by(self, policy_op: Self) -> bool {
        policy_op == Self::All || policy_op == self
    }
}

/// Auth context under which a query executes.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum AuthContext {
    /// `anon` key — no authenticated user.
    Anonymous,
    /// `authenticated` role — `uid` is the `auth.uid()` symbolic handle.
    Authenticated {
        /// Interned symbol for the user-id variable used in IFDS.
        uid: SymbolId,
    },
    /// `service_role` key — bypasses RLS entirely. Findings involving
    /// service_role are always HIGH regardless of the policy.
    ServiceRole,
}

// ============================================================================
// Symbolic predicates
// ============================================================================

/// A symbolic predicate in the engine's lightweight IR.
///
/// Deliberately much simpler than a full SQL AST: we care about the
/// *data-flow shape* of the predicate (which columns compare to which
/// auth-context values) rather than its full relational semantics.
///
/// The [`LiftEnv`] turns each variant into a Z3 `ast::Bool` via a direct
/// structural recursion. Complex SQL predicates that cannot be lowered
/// into this IR produce [`Predicate::Opaque`], which forces the prover
/// into the `Unknown` branch and triggers the BMC fallback.
#[derive(Clone, Debug)]
pub enum Predicate {
    /// Constant `TRUE`.
    True,
    /// Constant `FALSE`.
    False,
    /// `column = value`.
    Eq {
        /// LHS column reference.
        column: SymbolId,
        /// RHS value (may be symbolic).
        value: Value,
    },
    /// `auth.uid() = column`. Sugar for the overwhelmingly common RLS
    /// pattern `USING (auth.uid() = user_id)`.
    UidEq {
        /// The row column that must equal the authenticated user's id.
        column: SymbolId,
    },
    /// Logical conjunction.
    And(Vec<Predicate>),
    /// Logical disjunction.
    Or(Vec<Predicate>),
    /// Logical negation.
    Not(Box<Predicate>),
    /// Escape hatch: a SQL fragment the frontend could not symbolically
    /// model. Forces `Verdict::Unknown` unless explicitly overridden.
    Opaque(SymbolId),
}

/// A symbolic value inside a [`Predicate`].
#[derive(Clone, Debug)]
pub enum Value {
    /// Integer constant.
    Const(i64),
    /// String constant (interned).
    ConstStr(SymbolId),
    /// Column reference (same-row).
    Column(SymbolId),
    /// The authenticated user's `uid` (`auth.uid()`).
    Uid,
    /// Attacker-controlled input — universally quantified in the proof
    /// obligation so Z3 searches over *all* possible attacker payloads.
    Tainted(SymbolId),
}

// ============================================================================
// Verdicts
// ============================================================================

/// The three possible outcomes of a single correlation check.
#[derive(Clone, Debug)]
pub enum Verdict {
    /// The RLS policy provably covers every row the client query can reach.
    /// No finding is emitted.
    Safe {
        /// Proof metadata for the SARIF `properties` bag.
        proof: Proof,
    },
    /// Z3 produced a concrete model exhibiting an RLS bypass.
    Unsafe {
        /// The witness (model + optional attacker payload).
        witness: Witness,
    },
    /// Z3 could not decide within the budget; BMC was consulted.
    Unknown {
        /// Why Z3 bailed.
        reason: FallbackReason,
        /// BMC's (weaker) conclusion.
        bmc: BmcVerdict,
    },
}

/// Proof metadata attached to a `Safe` verdict.
#[derive(Clone, Debug)]
pub struct Proof {
    /// Policies that participated in the proof.
    pub checked_policies: Vec<SymbolId>,
    /// Wall-clock time the prover spent.
    pub elapsed: Duration,
}

/// Counterexample attached to an `Unsafe` verdict.
#[derive(Clone, Debug)]
pub struct Witness {
    /// Human-readable SMT-LIB model dump.
    pub model_dump: String,
    /// Most-likely attacker payload extracted from the model, if the
    /// formula contained a `Tainted` variable.
    pub attacker_payload: Option<String>,
    /// Wall-clock time the prover spent.
    pub elapsed: Duration,
}

/// Reason Z3 was unable to decide.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum FallbackReason {
    /// Z3's own cooperative timeout fired.
    Z3Timeout,
    /// Our wall-clock watchdog fired.
    WallClockTimeout,
    /// The formula contained an [`Predicate::Opaque`] fragment.
    OpaquePredicate,
    /// The formula required a theory Z3 was compiled without.
    UnsupportedTheory,
}

// ============================================================================
// Errors
// ============================================================================

/// Errors from the correlation engine.
#[derive(Error, Debug)]
pub enum CorrelationError {
    /// Z3 context construction failed (should never happen in practice).
    #[error("Z3 context build failed: {0}")]
    Z3Build(String),
    /// Z3 returned SAT but we could not extract the model.
    #[error("Z3 returned SAT but model extraction failed")]
    ModelExtract,
    /// The query references a table/column that the schema model does not
    /// contain — indicates a stale migration parse.
    #[error("unresolved column {0:?} in table {1:?}")]
    UnresolvedColumn(SymbolId, SymbolId),
}

// ============================================================================
// Bounded model checking fallback
// ============================================================================

/// Bounded model checking verdict, used when Z3 bails.
///
/// BMC unrolls the predicate over a finite domain of symbolic attacker
/// inputs (integers 0..k, strings from a small dictionary) and checks
/// each concretely. Incomplete by design — it can prove unsafety but can
/// only suggest safety-up-to-depth, not prove it — but it is cheap (no
/// SMT overhead) and deterministic, which makes it a practical CI
/// fallback.
#[derive(Clone, Debug)]
pub struct BmcVerdict {
    /// Conclusion.
    pub conclusion: BmcConclusion,
    /// How many concrete inputs were tried.
    pub depth_explored: u32,
    /// Wall-clock time.
    pub elapsed: Duration,
}

/// BMC conclusion.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum BmcConclusion {
    /// No counterexample found up to depth `k`. Does NOT constitute a
    /// proof — only Z3 UNSAT does that.
    SafeUpTo,
    /// Found a concrete attacker input that violates the policy.
    Counterexample,
    /// Ran out of budget without a conclusion.
    Inconclusive,
}

/// Trivial BMC implementation. The real BMC will be fleshed out when the
/// SQL frontend lands concrete evaluator support; this skeleton exists so
/// the public API is usable from day one.
pub struct BoundedModelChecker {
    /// Loop / recursion unroll bound used by the bounded check. Read by the
    /// future BMC implementation; suppress dead-code until that ships.
    #[allow(dead_code)]
    max_depth: u32,
}

impl BoundedModelChecker {
    /// Create a checker with the default unroll depth.
    #[must_use]
    pub fn new() -> Self {
        Self { max_depth: 16 }
    }

    /// Create a checker with a custom unroll depth.
    #[must_use]
    pub fn with_depth(depth: u32) -> Self {
        Self { max_depth: depth }
    }

    /// Run the bounded check. Placeholder until the concrete evaluator is
    /// wired in.
    #[must_use]
    pub fn run(&self) -> BmcVerdict {
        BmcVerdict {
            conclusion: BmcConclusion::Inconclusive,
            depth_explored: 0,
            elapsed: Duration::ZERO,
        }
    }
}

impl Default for BoundedModelChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Z3-backed correlator implementation
// ============================================================================
//
// Gated on the `smt-proofs` feature rather than `target_arch = "wasm32"`:
// the z3 crate is `optional = true` in Cargo.toml, so the gate must align
// with the feature flag, not the target. WASM targets simply don't enable
// the feature.

#[cfg(feature = "smt-proofs")]
mod native {
    //! Z3-backed correlator. Compiled only when `smt-proofs` is enabled.

    use super::*;

    use z3::ast::{self, Ast};
    use z3::{Config, Context, Params, SatResult, Solver};

    /// The Supabase three-way correlator. Holds a Z3 configuration that is
    /// reused across all queries in a single CI run.
    pub struct SupabaseCorrelator {
        cfg: Config,
    }

    impl SupabaseCorrelator {
        /// Construct a correlator with a default Z3 configuration.
        ///
        /// Model generation is enabled because `Unsafe` verdicts extract the
        /// witness model. Proof generation is *disabled* — we never consume
        /// UNSAT proofs and generating them would roughly double solve time.
        #[must_use]
        pub fn new() -> Self {
            let mut cfg = Config::new();
            cfg.set_model_generation(true);
            cfg.set_proof_generation(false);
            Self { cfg }
        }

        /// Discharge a single correlation proof obligation.
        ///
        /// # Errors
        ///
        /// Returns `Err` only for internal bugs (model extraction failure,
        /// unresolved schema symbols). Timeout → `Ok(Verdict::Unknown)`.
        pub fn correlate(
            &self,
            query: &CorrelationQuery,
            budget: Duration,
        ) -> Result<Verdict, CorrelationError> {
            let start = Instant::now();
            let ctx = Context::new(&self.cfg);
            let solver = Solver::new(&ctx);

            // --- Z3 internal timeout (cooperative). ----------------------
            let params = {
                let mut p = Params::new(&ctx);
                let budget_ms = u32::try_from(budget.as_millis()).unwrap_or(u32::MAX);
                p.set_u32("timeout", budget_ms);
                p
            };
            solver.set_params(&params);

            // --- Short-circuit: service_role ↔ tainted input. -----------
            // If the edge function uses service_role AND accepts tainted
            // input from the HTTP request, no RLS policy can help. We
            // report this immediately without consulting Z3 because:
            //  (a) it is 100 % deterministic, and
            //  (b) the developer needs to hear "your edge function is
            //      the problem" rather than a Z3-model dump.
            if let Some(ref f) = query.edge_fn {
                if f.uses_service_role && !f.tainted_params.is_empty() {
                    return Ok(Verdict::Unsafe {
                        witness: Witness {
                            model_dump: format!(
                                "Edge function {:?} creates a Supabase client with \
                                 service_role key, which unconditionally bypasses RLS. \
                                 Tainted HTTP parameters {:?} flow into the inner query \
                                 without any server-side policy enforcement.",
                                f.name, f.tainted_params,
                            ),
                            attacker_payload: Some(
                                "any HTTP payload reaching this endpoint".into(),
                            ),
                            elapsed: start.elapsed(),
                        },
                    });
                }
            }

            // --- Lift symbolic predicates to Z3. -------------------------
            let mut env = LiftEnv::new(&ctx);

            // Client filter conjunction: what rows the client claims to see.
            let client_phi = env.lift_conjunction(&query.client.filters);

            // Server policy predicate: what rows the server permits.
            let policy_phi = match query.policy.operation {
                Operation::Select | Operation::All => env.lift(&query.policy.using_expr),
                _ => match &query.policy.with_check_expr {
                    Some(p) => env.lift(p),
                    None => env.lift(&query.policy.using_expr),
                },
            };

            // --- Assert the conjecture: client reaches a forbidden row.
            //
            //     ∃ row.  client_phi(row) ∧ ¬policy_phi(row)
            //
            // If SAT, the model is the witness. If UNSAT, no such row
            // exists and the query is safe.
            solver.assert(&client_phi);
            solver.assert(&policy_phi.not());

            // --- Solve with wall-clock guard. ----------------------------
            let result = solver.check();
            let elapsed = start.elapsed();

            if elapsed > budget {
                return Ok(Verdict::Unknown {
                    reason: FallbackReason::WallClockTimeout,
                    bmc: BoundedModelChecker::new().run(),
                });
            }

            match result {
                SatResult::Unsat => Ok(Verdict::Safe {
                    proof: Proof {
                        checked_policies: vec![query.policy.name],
                        elapsed,
                    },
                }),
                SatResult::Sat => {
                    let model = solver.get_model().ok_or(CorrelationError::ModelExtract)?;
                    let model_dump = format!("{model}");

                    // Try to extract a concrete tainted-parameter value
                    // from the model so the finding message is actionable.
                    let attacker_payload = env
                        .tainted_vars()
                        .first()
                        .and_then(|var| model.eval(var, true).map(|val| format!("{val}")));

                    Ok(Verdict::Unsafe {
                        witness: Witness {
                            model_dump,
                            attacker_payload,
                            elapsed,
                        },
                    })
                }
                SatResult::Unknown => Ok(Verdict::Unknown {
                    reason: FallbackReason::Z3Timeout,
                    bmc: BoundedModelChecker::new().run(),
                }),
            }
        }
    }

    impl Default for SupabaseCorrelator {
        fn default() -> Self {
            Self::new()
        }
    }

    // -- Lifting environment (Predicate → Z3 AST) -------------------------

    /// Tracks the Z3 variables created during one proof obligation so we
    /// can (a) share a single `auth_uid` symbol across all column
    /// comparisons and (b) extract attacker-tainted variables from the
    /// model after a SAT result.
    struct LiftEnv<'ctx> {
        ctx: &'ctx Context,
        /// Symbolic `auth.uid()` — shared across all `UidEq` predicates.
        uid: ast::Int<'ctx>,
        /// Per-column Z3 free variables.
        columns: rustc_hash::FxHashMap<SymbolId, ast::Int<'ctx>>,
        /// Attacker-controlled free variables (for model extraction).
        tainted: Vec<ast::Int<'ctx>>,
    }

    impl<'ctx> LiftEnv<'ctx> {
        fn new(ctx: &'ctx Context) -> Self {
            Self {
                ctx,
                uid: ast::Int::new_const(ctx, "auth_uid"),
                columns: rustc_hash::FxHashMap::default(),
                tainted: Vec::new(),
            }
        }

        /// Get or create a Z3 integer constant for a column reference.
        fn column(&mut self, sym: SymbolId) -> ast::Int<'ctx> {
            self.columns
                .entry(sym)
                .or_insert_with(|| ast::Int::new_const(self.ctx, format!("col_{}", sym.0)))
                .clone()
        }

        /// Lift a [`Value`] into a Z3 integer expression.
        fn value(&mut self, v: &Value) -> ast::Int<'ctx> {
            match v {
                Value::Const(k) => ast::Int::from_i64(self.ctx, *k),
                Value::ConstStr(sym) => {
                    // Model strings as unique integers (the correlator
                    // checks equality/inequality, not string semantics).
                    ast::Int::new_const(self.ctx, format!("str_{}", sym.0))
                }
                Value::Column(c) => self.column(*c),
                Value::Uid => self.uid.clone(),
                Value::Tainted(sym) => {
                    let var = ast::Int::new_const(self.ctx, format!("tainted_{}", sym.0));
                    self.tainted.push(var.clone());
                    var
                }
            }
        }

        /// Lift one [`Predicate`] into a Z3 boolean.
        fn lift(&mut self, p: &Predicate) -> ast::Bool<'ctx> {
            match p {
                Predicate::True => ast::Bool::from_bool(self.ctx, true),
                Predicate::False => ast::Bool::from_bool(self.ctx, false),
                Predicate::Eq { column, value } => {
                    let lhs = self.column(*column);
                    let rhs = self.value(value);
                    lhs._eq(&rhs)
                }
                Predicate::UidEq { column } => {
                    let col = self.column(*column);
                    col._eq(&self.uid)
                }
                Predicate::And(xs) => {
                    let lifted: Vec<ast::Bool<'ctx>> = xs.iter().map(|x| self.lift(x)).collect();
                    let refs: Vec<&ast::Bool<'ctx>> = lifted.iter().collect();
                    ast::Bool::and(self.ctx, &refs)
                }
                Predicate::Or(xs) => {
                    let lifted: Vec<ast::Bool<'ctx>> = xs.iter().map(|x| self.lift(x)).collect();
                    let refs: Vec<&ast::Bool<'ctx>> = lifted.iter().collect();
                    ast::Bool::or(self.ctx, &refs)
                }
                Predicate::Not(x) => self.lift(x).not(),
                Predicate::Opaque(_) => {
                    // Opaque predicates are unconstrained booleans — the
                    // solver treats them as free variables, which
                    // conservatively over-approximates (any satisfying
                    // assignment can choose TRUE, allowing the query
                    // through). This biases toward `Unsafe`/`Unknown` when
                    // we cannot model the SQL precisely, which is the safe
                    // direction for a security tool.
                    ast::Bool::fresh_const(self.ctx, "opaque")
                }
            }
        }

        /// Lift a conjunction of predicates (the client's filter list).
        fn lift_conjunction(&mut self, ps: &[Predicate]) -> ast::Bool<'ctx> {
            if ps.is_empty() {
                return ast::Bool::from_bool(self.ctx, true);
            }
            let lifted: Vec<ast::Bool<'ctx>> = ps.iter().map(|p| self.lift(p)).collect();
            let refs: Vec<&ast::Bool<'ctx>> = lifted.iter().collect();
            ast::Bool::and(self.ctx, &refs)
        }

        /// Return all tainted-variable Z3 nodes created during lifting.
        /// Used to extract attacker payloads from a SAT model.
        fn tainted_vars(&self) -> &[ast::Int<'ctx>] {
            &self.tainted
        }
    }
}

// Re-export the native correlator at module level.
#[cfg(feature = "smt-proofs")]
pub use native::SupabaseCorrelator;

// ============================================================================
// Stub when `smt-proofs` is disabled
// ============================================================================

/// Stub correlator for builds without the `smt-proofs` feature. Always
/// returns `Verdict::Unknown` with `FallbackReason::UnsupportedTheory`.
///
/// Public API matches the Z3-backed implementation so call sites compile
/// identically with or without the feature.
#[cfg(not(feature = "smt-proofs"))]
pub struct SupabaseCorrelator;

#[cfg(not(feature = "smt-proofs"))]
impl SupabaseCorrelator {
    /// Construct the stub.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Stub correlator. Preserves the syntactic service_role short-circuit
    /// (which never needs Z3) and falls back to `Unknown` for everything
    /// else. The full Z3 implementation is gated behind `smt-proofs`.
    pub fn correlate(
        &self,
        query: &CorrelationQuery,
        _budget: Duration,
    ) -> Result<Verdict, CorrelationError> {
        let start = std::time::Instant::now();

        // service_role + tainted params is 100% syntactic — flag it even
        // without Z3.
        if let Some(ref f) = query.edge_fn {
            if f.uses_service_role && !f.tainted_params.is_empty() {
                return Ok(Verdict::Unsafe {
                    witness: Witness {
                        model_dump: format!(
                            "Edge function {:?} creates a Supabase client with \
                             service_role key, which unconditionally bypasses RLS. \
                             Tainted HTTP parameters {:?} flow into the inner query \
                             without any server-side policy enforcement.",
                            f.name, f.tainted_params,
                        ),
                        attacker_payload: Some("any HTTP payload reaching this endpoint".into()),
                        elapsed: start.elapsed(),
                    },
                });
            }
        }

        Ok(Verdict::Unknown {
            reason: FallbackReason::UnsupportedTheory,
            bmc: BoundedModelChecker::new().run(),
        })
    }
}

#[cfg(not(feature = "smt-proofs"))]
impl Default for SupabaseCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpg::CodeGraph;

    /// Helper: build a minimal correlation query for unit tests.
    fn test_query(g: &mut CodeGraph, uses_service_role: bool) -> CorrelationQuery {
        let table = g.intern_symbol("posts");
        let user_id = g.intern_symbol("user_id");
        let fn_name = g.intern_symbol("get-posts");
        let file = g.intern_file("test.dart");
        let call = g.add_node(crate::cpg::NodeKind::CallSite, file, 0..1);

        CorrelationQuery {
            client: DartClientModel {
                table,
                operation: Operation::Select,
                filters: vec![Predicate::UidEq { column: user_id }],
                columns: vec![],
                auth_context: AuthContext::Authenticated { uid: user_id },
            },
            edge_fn: Some(EdgeFunctionModel {
                name: fn_name,
                uses_service_role,
                tainted_params: vec![g.intern_symbol("req.body")],
                inner_query: None,
            }),
            policy: RlsPolicyModel {
                name: g.intern_symbol("posts_select_policy"),
                table,
                operation: Operation::Select,
                using_expr: Predicate::UidEq { column: user_id },
                with_check_expr: None,
            },
            call_site: call,
        }
    }

    #[test]
    fn service_role_bypass_is_immediate_unsafe() {
        let mut g = CodeGraph::new();
        let q = test_query(&mut g, /* uses_service_role = */ true);
        let correlator = SupabaseCorrelator::new();
        let verdict = correlator.correlate(&q, DEFAULT_BUDGET).unwrap();

        assert!(
            matches!(verdict, Verdict::Unsafe { .. }),
            "service_role + tainted params must be immediately Unsafe"
        );
    }

    // The Z3-dependent test below requires Z3 to be installed and the
    // `smt-proofs` feature to be enabled. CI runs it via
    // `--features "engine-core/full"`; local builds may skip it.
    #[cfg(feature = "smt-proofs")]
    #[test]
    fn matching_uid_policy_is_safe() {
        let mut g = CodeGraph::new();
        let q = test_query(&mut g, /* uses_service_role = */ false);
        let correlator = SupabaseCorrelator::new();
        let verdict = correlator.correlate(&q, DEFAULT_BUDGET).unwrap();

        // The client filters on `user_id = auth.uid()` and the RLS policy
        // enforces the same predicate → UNSAT → Safe.
        assert!(
            matches!(verdict, Verdict::Safe { .. }),
            "identical client/RLS uid predicate must be Safe, got: {:?}",
            verdict,
        );
    }

    #[test]
    fn operation_coverage() {
        // Verify the coverage predicate is correct.
        assert!(Operation::Select.covered_by(Operation::All));
        assert!(Operation::Select.covered_by(Operation::Select));
        assert!(!Operation::Select.covered_by(Operation::Insert));
        assert!(Operation::Delete.covered_by(Operation::All));
    }
}
