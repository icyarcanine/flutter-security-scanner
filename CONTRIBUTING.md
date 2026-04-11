# Contributing to fluttersupabasehelper

We welcome contributions to make the scanning engine more precise.

## Setup

1. Clone the repository locally.
2. Run `dart pub get` to download dependencies.
3. Validate your setup runs successfully using `dart run bin/fluttersupabasehelper.dart .`

## Running tests

Run the built-in smoke tests before committing any changes:

```bash
dart run tool/smoke_test.dart
```

This runs the engine against `test/fixtures` to prevent regressions.

## Adding a rule

1. Create a new Dart file in `lib/src/rules/` under the appropriate category (`security/`, `config/`, or `supabase/`).
2. Extend the base `Rule` class.
3. Implement the `evaluate(ProjectContext context)` method to return a list of `Finding`s.
4. Add your new rule to the master registry found in `lib/src/engine.dart`.
5. Add a test payload to `test/fixtures/broken_app/lib/main.dart` or a fresh fixture.
6. Register the failure expectation in `tool/smoke_test.dart`.
