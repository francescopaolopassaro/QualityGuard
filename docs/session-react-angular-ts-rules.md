# Session: React, Angular, TS-specific rules for QualityGuard

**Date:** 2026-08-31

## Goal

Expand QualityGuard's JS/TS coverage with framework-specific rules (React, Angular) and TS-specific rules.

## What was done

### React Rules (`src/QualityGuard.Core/Rules/Languages/ReactRules.cs` - 6 rules)

| Key | Rule | Issue |
|---|---|---|
| `QG-JS-SEC-0100` | `ReactDangerouslySetInnerHtmlRule` | XSS via `dangerouslySetInnerHTML` |
| `QG-JS-SML-0639` | `ReactMissingKeyPropRule` | array index as `key` anti-pattern |
| `QG-JS-SML-0432` | `ReactDirectDomAccessRule` | `querySelector`/`getElementById` breaks virtual DOM |
| `QG-JS-SEC-0101` | `ReactWindowStateOpenRule` | `window.open` without `noopener` |
| `QG-JS-BUG-0220` | `ReactHookArrayDependencyRule` | inline array as hook dependency causes infinite re-render |
| `QG-JS-BUG-0221` | `ReactUseEffectMissingCleanupRule` | `subscribe()` without `unsubscribe` in `useEffect` |

### Angular Rules (`src/QualityGuard.Core/Rules/Languages/AngularRules.cs` - 4 rules)

| Key | Rule | Issue |
|---|---|---|
| `QG-TS-SEC-0006` | `AngularBypassSecurityTrustRule` | `bypassSecurityTrust*` disables XSS sanitization |
| `QG-TS-SML-0007` | `AngularMissingOnDestroyRule` | Observable `subscribe()` without `ngOnDestroy` |
| `QG-TS-SML-0008` | `AngularElementRefNativeElementRule` | direct DOM access via `.nativeElement` |
| `QG-TS-SEC-0007` | `AngularEvalUsageRule` | `eval()` in Angular components |

### TS-Specific Rules (`src/QualityGuard.Core/Rules/Languages/TsSpecificRules.cs` - 4 rules)

| Key | Rule | Issue |
|---|---|---|
| `QG-TS-SEC-0008` | `TsWeakHashingRule` | MD5/SHA1 usage in `crypto.createHash` |
| `QG-TS-SML-0009` | `TsNonNullableAssertionRule` | `!` non-null assertion bypasses null checks |
| `QG-TS-SML-0010` | `TsRedundantTypeCastRule` | `x as typeof x` is redundant |
| `QG-TS-BUG-0016` | `TsOptionalChainingAssignmentRule` | `obj?.prop = value` is invalid TS |

## Build fixes

- Added `HasTree` method to `ReactRuleBase` and `AngularRuleBase` (inherited from `context.Tree.HasDedicatedParser`)
- Added `using System.Text.RegularExpressions` to `ReactRules.cs` and `TsSpecificRules.cs`
- Fixed `TokenKind.Name` → `TokenKind.Identifier` (enum doesn't have `Name`)
- Fixed duplicate key `QG-JS-SML-0168` (conflicted with `JsTsPackRules.cs`) → reassigned to `QG-JS-SML-0639`
- Removed `"ok"` from `CallableMatchers` in `JsIncompleteAssertionRule` — `ok` is a Chai BDD property assertion (reads as correct), not a callable method
- Updated `rule-ids.json`: `TS-SEC` → 9, `TS-SML` → 11, `TS-BUG` → 17

## Results

- **808/808 tests pass**
- JS recall: **3.2%** (1027 annotated lines, 33 reported)
- TS recall: **6.5%** (1021 annotated lines, 66 reported)
- Recall unchanged because:
  - Annotated corpus has no React/Angular test fixtures
  - TS top misses (S6437 secrets, S1874 deprecated, S1226 parameter shadowing) need type analysis

## Key files modified

| File | Change |
|---|---|
| `src/QualityGuard.Core/Rules/Languages/ReactRules.cs` | **New** - 6 React rules |
| `src/QualityGuard.Core/Rules/Languages/AngularRules.cs` | **New** - 4 Angular rules |
| `src/QualityGuard.Core/Rules/Languages/TsSpecificRules.cs` | **New** - 4 TS-specific rules |
| `src/QualityGuard.Core/Rules/BuiltInRuleRegistrar.cs` | Registered `ReactRuleSet`, `AngularRuleSet`, `TsSpecificRuleSet` |
| `src/QualityGuard.Core/Rules/Languages/JsTsMeasuredRules.cs` | Removed `ok` from `CallableMatchers` |
| `rule-ids.json` | TS registry bumped (SEC 9, SML 11, BUG 17) |

## Next steps

### TS recall is limited by parser

The annotated TS corpus's top missed checks require type analysis the parser doesn't support:

| Check | Lines | Why missed |
|---|---|---|
| S6437 | 41 | Hardcoded crypto secrets — needs taint analysis |
| S8479 | 35 | Framework-specific |
| S1874 | 35 | Deprecated API — needs JSDoc `@deprecated` reading |
| S1226 | 30 | Parameter shadowing — needs scope resolution |
| S6551 | 29 | `Object.toString()` default — needs type analysis |

### JS recall is limited by module resolution

| Check | Lines | Why missed |
|---|---|---|
| S2970 | 120 | Incomplete assertions — needs module/type resolution |
| S5332 | 54 | Cleartext protocols — partially covered |
| S6303 | 40 | Cloud resources without encryption |
| S4790 | 35 | Hashing algorithms |
| S6308 | 32 | Cloud resources publicly reachable |

### Potential improvements

- Convert more token-based rules to AST-based
- Add module resolution awareness (track imports/exports)
- Add type inference for common patterns (React hooks, Angular lifecycle)
- Target framework-specific checks in React/Angular test fixtures
