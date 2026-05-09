# Flutter+Supabase Security Scanner — Roadmap to 100/100

## Honest Assessment

100/100 is a theoretical maximum — there will always be edge cases, new Supabase features, and evolving Flutter security patterns. **Realistic target: 90-95/100**, which would make this the best security scanner for Flutter+Supabase in existence.

## Critical Blockers (must fix first)

### 1. Rust Engine Returns Empty on Test Fixtures
**Root cause:** Semgrep YAML rules don't define function parameters as taint sources. The test fixture uses `String userInput` parameter, but the rule only looks for `TextEditingController.text`, `stdin.readLineSync()`, etc.
**Fix:** Add generic function parameter source patterns to Semgrep rules, OR make the Rust engine treat all function parameters as potential sources (like the TS tracker does).

### 2. Intra-Procedural Limitation
**Root cause:** The `source_in_same_file` check in `main.rs` line ~240 kills cross-file flows.
**Fix:** Remove or relax this check for the default analysis path.

### 3. Missing Flutter-Specific Rules
Currently missing:
- Android Intent injection / exported activities
- Content provider exposure
- Network security config (Android)
- App Transport Security (iOS) exceptions
- ProGuard/R8 obfuscation rules
- Local notification security
- Background task security
- Image/file picker path traversal
- State management auth leaks (BLoC/Riverpod/Provider)
- Widget lifecycle disposal
- Camera/microphone permission data handling

### 4. Missing Supabase Integration Rules
Currently missing:
- Auth flow PKCE validation
- Token refresh / rotation patterns
- Sign-out completeness (clearing all state)
- Offline-first local cache encryption
- Realtime auth token refresh on reconnect
- Edge function JWT validation
- Webhook signature verification
- Database trigger security
- Storage upload type/size validation
- Supabase error message sanitization

### 5. Missing Supply Chain Scanning
- pubspec.yaml dependency vulnerability checking
- Known CVEs in Flutter/Dart packages
- Typosquatting detection for pub.dev

## Implementation Plan

### Phase 1: Fix the Rust Engine (highest leverage)
1. Add function parameter sources to Semgrep YAML rules
2. Remove `source_in_same_file` restriction
3. Verify end-to-end SQL injection detection on test fixtures
4. Add command injection and XSS rule coverage in Rust engine

### Phase 2: Expand Rule Coverage
1. Add 20+ new Flutter-specific rules
2. Add 15+ new Supabase integration rules
3. Add dependency scanning rules
4. Ensure every rule has test fixtures

### Phase 3: Harden Existing Rules
1. Improve RLS detection with edge cases
2. Add more secret patterns (Supabase service role, JWT secrets)
3. Improve false positive control
4. Add confidence levels to all findings

### Phase 4: Production Readiness
1. Comprehensive documentation
2. CI/CD integration guides
3. Performance benchmarks
4. Known limitation documentation

## Success Criteria

A 90-95/100 scanner for Flutter+Supabase means:
- **Zero false negatives** on all test fixtures
- **<5% false positive rate** on real-world projects
- **Coverage of all OWASP Mobile Top 10** for Flutter
- **Coverage of all Supabase security best practices**
- **Working Rust engine** with inter-procedural analysis
- **Clear documentation** for production use

## Current Score Breakdown

| Area | Current | Target | Gap |
|------|---------|--------|-----|
| Supabase RLS | 80 | 95 | +15 |
| Supabase RPC/Functions | 70 | 95 | +25 |
| Supabase Storage | 60 | 90 | +30 |
| Supabase Auth | 40 | 90 | +50 |
| Supabase Realtime | 70 | 90 | +20 |
| Flutter Platform Security | 65 | 90 | +25 |
| Flutter Data Protection | 70 | 90 | +20 |
| Flutter Network Security | 60 | 90 | +30 |
| Flutter Injection Prevention | 40 | 85 | +45 |
| Flutter+Supabase Integration | 50 | 90 | +40 |
| Dependency Security | 0 | 70 | +70 |
| **Overall** | **~55** | **~90** | **+35** |
