//! Dart type arena — the semantic backbone of the engine.
//!
//! The CPG stores only opaque [`TypeId`] handles on each node. This module
//! owns the actual type information: class names, library URIs, supertype
//! chains, generic type arguments, and nullability. Every downstream pass
//! that needs to answer "is this a `StreamController`?" or "does this class
//! extend `ConsumerWidget`?" queries the [`TypeArena`] through its
//! [`TypeArena::is_subtype`] method, which walks the pre-computed supertype
//! chain in O(depth) — typically ≤ 5 hops for Flutter framework types.
//!
//! The arena is populated by the [`super::dart_analyzer`] bridge, which
//! streams resolved type descriptors from the Dart SDK's `package:analyzer`.

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::cpg::TypeId;

// ============================================================================
// Type descriptors
// ============================================================================

/// Full metadata for one Dart type, interned into the arena.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeEntry {
    /// Canonical form: `dart:async#StreamController<String>`.
    pub canonical: Box<str>,
    /// Unparameterised name: `StreamController`.
    pub name: Box<str>,
    /// Library URI: `dart:async`, `package:flutter_bloc/flutter_bloc.dart`.
    pub library: Box<str>,
    /// Resolved supertype chain (direct supertypes first, `Object` last).
    /// Used by [`TypeArena::is_subtype`].
    pub supertypes: Vec<TypeId>,
    /// Generic type arguments. Empty for non-generic types.
    pub type_args: Vec<TypeId>,
    /// Whether this is a nullable type (`T?`).
    pub is_nullable: bool,
}

/// Lightweight type descriptor deserialized from the Dart analyzer bridge's
/// JSON output. Converted into a [`TypeEntry`] + [`TypeId`] by
/// [`TypeArena::intern_from_desc`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DartTypeDesc {
    /// Unparameterised name.
    pub name: String,
    /// Library URI.
    pub library: String,
    /// Generic type arguments (recursive).
    #[serde(default)]
    pub type_args: Vec<DartTypeDesc>,
    /// Nullable (`T?`).
    #[serde(default)]
    pub is_nullable: bool,
    /// Supertype names in `library#Name` form, from direct parent to root.
    #[serde(default)]
    pub supertypes: Vec<String>,
}

// ============================================================================
// Arena
// ============================================================================

/// The type arena. Owns every [`TypeEntry`] and provides O(1) lookup by
/// [`TypeId`] and O(depth) subtype checks.
///
/// Thread-safety: the arena is built single-threaded during the frontend
/// phase and then shared immutably during analysis. No interior mutability.
pub struct TypeArena {
    /// Dense storage indexed by `TypeId.0`.
    entries: Vec<TypeEntry>,
    /// Canonical string → `TypeId` for dedup during construction.
    by_canonical: FxHashMap<Box<str>, TypeId>,
}

impl TypeArena {
    /// Create an empty arena.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(4096),
            by_canonical: FxHashMap::default(),
        }
    }

    /// Intern a type from a [`DartTypeDesc`] received from the analyzer
    /// bridge. Returns the stable [`TypeId`]. Deduplicates by canonical
    /// name so multiple references to `StreamController<String>` share one
    /// entry.
    pub fn intern_from_desc(&mut self, desc: &DartTypeDesc) -> TypeId {
        let canonical = Self::canonical_name(desc);
        if let Some(&id) = self.by_canonical.get(canonical.as_str()) {
            return id;
        }

        // Intern type args first (recursive).
        let type_args: Vec<TypeId> = desc
            .type_args
            .iter()
            .map(|a| self.intern_from_desc(a))
            .collect();

        // Intern supertypes. At this stage we may not have full entries for
        // all supertypes yet (they arrive in a later record), so we create
        // stub entries keyed only on canonical name. The resolver pass
        // patches them when the full descriptor arrives.
        let supertypes: Vec<TypeId> = desc
            .supertypes
            .iter()
            .map(|s| self.intern_stub(s))
            .collect();

        let id = TypeId(u32::try_from(self.entries.len()).expect("type arena overflow"));
        let boxed: Box<str> = canonical.into();
        self.entries.push(TypeEntry {
            canonical: boxed.clone(),
            name: desc.name.as_str().into(),
            library: desc.library.as_str().into(),
            supertypes,
            type_args,
            is_nullable: desc.is_nullable,
        });
        self.by_canonical.insert(boxed, id);
        id
    }

    /// Intern a stub type entry from a canonical name string. If the type
    /// already exists, returns the existing id. Otherwise creates a minimal
    /// entry that will be patched when the full descriptor arrives.
    pub fn intern_stub(&mut self, canonical: &str) -> TypeId {
        if let Some(&id) = self.by_canonical.get(canonical) {
            return id;
        }
        let id = TypeId(u32::try_from(self.entries.len()).expect("type arena overflow"));
        // Parse the canonical form `library#Name` into library + name.
        let (library, name) = canonical.split_once('#').unwrap_or(("", canonical));
        let boxed: Box<str> = canonical.into();
        self.entries.push(TypeEntry {
            canonical: boxed.clone(),
            name: name.into(),
            library: library.into(),
            supertypes: Vec::new(),
            type_args: Vec::new(),
            is_nullable: false,
        });
        self.by_canonical.insert(boxed, id);
        id
    }

    // -- queries ----------------------------------------------------------

    /// Look up a type entry by id.
    #[inline]
    #[must_use]
    pub fn get(&self, id: TypeId) -> &TypeEntry {
        &self.entries[id.0 as usize]
    }

    /// Look up a type by canonical name.
    #[must_use]
    pub fn lookup(&self, canonical: &str) -> Option<TypeId> {
        self.by_canonical.get(canonical).copied()
    }

    /// Is `child` a subtype of the type identified by `ancestor_canonical`?
    ///
    /// Walks the pre-computed `supertypes` chain. Returns `true` if any
    /// entry in the chain has a canonical name that matches
    /// `ancestor_canonical`, OR if `child` itself matches. O(depth).
    #[must_use]
    pub fn is_subtype(&self, child: TypeId, ancestor_canonical: &str) -> bool {
        let entry = self.get(child);
        // Direct match (possibly ignoring type args).
        if self.canonical_matches(&entry.canonical, ancestor_canonical) {
            return true;
        }
        // Walk supertypes.
        for &sup in &entry.supertypes {
            let sup_entry = self.get(sup);
            if self.canonical_matches(&sup_entry.canonical, ancestor_canonical) {
                return true;
            }
        }
        false
    }

    // -- convenience predicates -------------------------------------------

    /// Is this type a `dart:async#StreamController` (or subclass)?
    #[must_use]
    pub fn is_stream_controller(&self, t: TypeId) -> bool {
        self.is_subtype(t, "dart:async#StreamController")
    }

    /// Is this type a `dart:async#StreamSink`?
    #[must_use]
    pub fn is_stream_sink(&self, t: TypeId) -> bool {
        self.is_subtype(t, "dart:async#StreamSink")
    }

    /// Is this type a `dart:async#Stream`?
    #[must_use]
    pub fn is_stream(&self, t: TypeId) -> bool {
        self.is_subtype(t, "dart:async#Stream")
    }

    /// Is this a Riverpod `StateNotifier` (from either `riverpod` or
    /// `state_notifier` packages)?
    #[must_use]
    pub fn is_state_notifier(&self, t: TypeId) -> bool {
        self.is_subtype(t, "package:riverpod/src/state_notifier.dart#StateNotifier")
            || self.is_subtype(
                t,
                "package:state_notifier/state_notifier.dart#StateNotifier",
            )
    }

    /// Is this a Riverpod `Notifier` (Riverpod 2.0+)?
    #[must_use]
    pub fn is_riverpod_notifier(&self, t: TypeId) -> bool {
        self.is_subtype(t, "package:riverpod/src/notifier.dart#Notifier")
            || self.is_subtype(
                t,
                "package:riverpod_annotation/riverpod_annotation.dart#Notifier",
            )
    }

    /// Is this a `flutter_bloc` `BlocBase` (parent of both `Bloc` and `Cubit`)?
    #[must_use]
    pub fn is_bloc_base(&self, t: TypeId) -> bool {
        self.is_subtype(t, "package:bloc/src/bloc_base.dart#BlocBase")
            || self.is_subtype(t, "package:flutter_bloc/flutter_bloc.dart#BlocBase")
    }

    /// Is this a Flutter `ChangeNotifier`?
    #[must_use]
    pub fn is_change_notifier(&self, t: TypeId) -> bool {
        self.is_subtype(
            t,
            "package:flutter/src/foundation/change_notifier.dart#ChangeNotifier",
        )
    }

    /// Is this a `ConsumerWidget` or `ConsumerStatefulWidget` (Riverpod)?
    #[must_use]
    pub fn is_consumer_widget(&self, t: TypeId) -> bool {
        self.is_subtype(
            t,
            "package:flutter_riverpod/src/consumer.dart#ConsumerWidget",
        ) || self.is_subtype(
            t,
            "package:flutter_riverpod/src/consumer.dart#ConsumerStatefulWidget",
        ) || self.is_subtype(
            t,
            "package:hooks_riverpod/hooks_riverpod.dart#HookConsumerWidget",
        )
    }

    /// Is this a `ValueNotifier`?
    #[must_use]
    pub fn is_value_notifier(&self, t: TypeId) -> bool {
        self.is_subtype(
            t,
            "package:flutter/src/foundation/change_notifier.dart#ValueNotifier",
        )
    }

    /// Number of types in the arena.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the arena empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // -- internal ---------------------------------------------------------

    /// Build the canonical name string for a type descriptor.
    fn canonical_name(desc: &DartTypeDesc) -> String {
        let mut s = format!("{}#{}", desc.library, desc.name);
        if !desc.type_args.is_empty() {
            s.push('<');
            for (i, arg) in desc.type_args.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&Self::canonical_name(arg));
            }
            s.push('>');
        }
        if desc.is_nullable {
            s.push('?');
        }
        s
    }

    /// Does a canonical name match? Supports two forms of matching:
    /// - Exact: `dart:async#StreamController<String>` == same
    /// - Base-only: `dart:async#StreamController` matches any parameterisation
    fn canonical_matches(&self, full: &str, pattern: &str) -> bool {
        if full == pattern {
            return true;
        }
        // If the pattern has no `<`, treat it as a base-name match: strip
        // the type args from `full` and compare.
        if !pattern.contains('<') {
            let base = full.split('<').next().unwrap_or(full);
            // Also strip trailing `?` from the base.
            let base = base.trim_end_matches('?');
            let pattern_clean = pattern.trim_end_matches('?');
            return base == pattern_clean;
        }
        false
    }
}

impl Default for TypeArena {
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

    #[test]
    fn intern_and_subtype_check() {
        let mut arena = TypeArena::new();

        // Simulate: ChangeNotifier extends Listenable
        let listenable_id = arena.intern_stub("package:flutter#Listenable");
        let cn_desc = DartTypeDesc {
            name: "ChangeNotifier".into(),
            library: "package:flutter/src/foundation/change_notifier.dart".into(),
            type_args: vec![],
            is_nullable: false,
            supertypes: vec!["package:flutter#Listenable".into()],
        };
        let cn_id = arena.intern_from_desc(&cn_desc);

        assert!(arena.is_subtype(
            cn_id,
            "package:flutter/src/foundation/change_notifier.dart#ChangeNotifier"
        ));
        assert!(arena.is_subtype(cn_id, "package:flutter#Listenable"));
        assert!(!arena.is_subtype(cn_id, "dart:async#StreamController"));
        let _ = listenable_id; // used via intern_stub
    }

    #[test]
    fn generic_base_matching() {
        let mut arena = TypeArena::new();
        let desc = DartTypeDesc {
            name: "StreamController".into(),
            library: "dart:async".into(),
            type_args: vec![DartTypeDesc {
                name: "String".into(),
                library: "dart:core".into(),
                type_args: vec![],
                is_nullable: false,
                supertypes: vec![],
            }],
            is_nullable: false,
            supertypes: vec![],
        };
        let id = arena.intern_from_desc(&desc);
        // Base-name match (no type args in pattern).
        assert!(arena.is_subtype(id, "dart:async#StreamController"));
    }
}
