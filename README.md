# ⚖️ QualityGuard

<img width="1197" height="766" alt="qualityguard_splash" src="https://github.com/francescopaolopassaro/QualityGuard/blob/main/imgs/qualityguard.svg" />

**QualityGuard** is a stateless, in-memory code quality engine written in C# for continuous integration pipelines. It parses source code, computes metrics, runs static analysis rules, evaluates a configurable Quality Gate, and exits with `PASSED` or `FAILED` — no background service, database, or UI required.

```bash
dotnet run --project src/QualityGuard.Cli -- --path ./src --by-folder

```

It packs **4079 rules across 27 languages** (including **653 security rules**), executing on real syntax trees with a semantic model, project index, and interprocedural taint analysis. Coverage extends beyond core languages to cloud infrastructure (AWS, Azure, and Google Cloud via Terraform and CloudFormation), Kubernetes manifests, Dockerfiles, Android manifests, Gradle scripts, Java EE and ASP.NET descriptors, WordPress configurations, and .NET frameworks (Entity Framework, Dapper, ASP.NET Core, Blazor, MAUI, WPF, WinUI, and Avalonia).

Rules ship in a **default profile** — convention and stylistic checks stay disabled until explicitly requested with `--all-rules`, preventing noisy reports from masking critical defects.

Engine engineering prioritizes precision: rules are vetted on third-party production codebases before inclusion, noisy checks are rewritten on the syntax tree or dropped, and fixed false positives are locked in place with regression tests (§8).

### Security is organized around the OWASP

Every security rule carries its OWASP category, so CLI reports and SARIF exports group findings
by the standard your auditors speak. Injection-style rules run through the data-flow engine: they
fire only when untrusted input actually reaches the sink, which keeps framework code quiet.
Detection is scored continuously against the intentionally vulnerable OWASP Benchmark corpus -
the numbers that guide each release are recall and false-positive rate on those 2,740 cases.

---

## 1. Packages

| Project | Responsibility |
| --- | --- |
| `QualityGuard.Core` | Domain models, tokenizers, parsers, semantic model, taint analysis, duplication engine, rule framework, and gate evaluator. |
| `QualityGuard.Sources.Sarif` | Reader and writer for **SARIF 2.1.0**: imports external metrics, exports findings and gate verdicts. |
| `QualityGuard.Cli` | Pipeline entry point executable with explicit exit codes. |
| `QualityGuard.Mcp` | **Model Context Protocol server** (`net10.0`): exposes scans, gate state, and AI-formatted Markdown reports over stdio or Streamable HTTP for local agents (Claude Code, OpenCode, Codex, Copilot). |

All four projects ship as NuGet packages (`1.0.0`) via `scripts/publish-nuget.ps1`, which packs in dependency order and pushes on demand. The MCP server consumes the core packages from NuGet and operates fully standalone.

---

## 2. Analysis pipeline

Single-file execution sequence:

```
tokenize → syntax tree → semantic model → taint → metrics

```

Cross-project analysis sequence:

```
project index → type resolution → interprocedural taint → rules → quality gate

```

* **Syntax tree** — Recursive-descent parsers handle C#, VB.NET, Java, Go, JavaScript, TypeScript, PHP, Kotlin, and Dart (using a shared C-family base parser with dialect drivers), alongside an indentation-driven parser for Python. Other languages (Swift, Ruby, Rust, C/C++, shell, SQL) fall back to a generic structural parser that isolates declarations, blocks, and control flow. `SyntaxTree.HasDedicatedParser` signals to rules whether statement-level precision is available; rules requiring high precision remain silent when operating on structural fallbacks.
* **Semantic model** — Resolves scopes, symbols, and usages. Links declarations, assignments, and reads so rules evaluate underlying symbols rather than matching raw identifiers.
* **Project index** — Tracks types, inheritance hierarchies, members, return types, and reference counts across all scanned files to enable cross-file analysis.
* **Type resolution** — Performs best-effort expression typing. Returns `null` when a type cannot be resolved deterministically; rules suppress output on unresolved types to avoid guessing.
* **Taint analysis** — Tracks untrusted sources (request input, environment variables, argv, superglobals), propagation pathing through assignments and function calls, sanitizers, and sinks. Runs **interprocedurally**: functions returning untrusted data act as sources across call sites, and tainted arguments flow into matching parameters in external files. Findings include complete source-to-sink flow paths.
* **Duplication** — Uses lexical tokenization combined with sliding-window hashing, requiring no compilation phase.

---

## 3. Domain model

* **`Metric` / `CoreMetrics**` — Per-file metrics aggregated across the scan. Quality Gate evaluation focuses on incremental changes: `new_coverage`, `new_duplicated_lines_density`, `new_security_rating`, `new_reliability_rating`, `new_maintainability_rating`, `new_security_hotspots_reviewed`.
* **`Condition`** — Single gate assertion: target `metricKey`, operator (`LESS_THAN`, `GREATER_THAN`), and numeric `threshold`.
* **`QualityGateResult`** — Top-level verdict alongside detailed condition checks and messages.
* **`Severity`** — `BLOCKER`, `CRITICAL`, `MAJOR`, `MINOR`, `INFO`.
* **Issue kinds** — `Bug`, `Vulnerability`, `SecurityHotspot`, `CodeSmell`.
* **Technical debt** — Estimated remediation time assigned to each finding.

### Evaluation

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────────────┐
│  MetricReader   │ ---> │    Evaluator     │ ---> │    StatusCalculator     │
│ (Reads metrics) │      │(Evaluates rules) │      │ (Outputs PASSED/FAILED) │
└─────────────────┘      └──────────────────┘      └─────────────────────────┘

```

A scan fails (`FAILED`) if **at least one** gate condition breaches its threshold.

### Quality numbers

Metrics derive directly from reported findings, mapping directly back to source lines. The CLI displays these results upon scan completion:

| Number | How it is computed |
| --- | --- |
| Bugs / vulnerabilities / hotspots / code smells | Aggregated count by issue type, grouped by severity. |
| **Reliability rating** | Driven by the **worst** detected bug: A = none, B = minor, C = major, D = critical, E = blocker. |
| **Security rating** | Driven by the worst detected vulnerability using the same scale. |
| **Technical debt** | Cumulative remediation time of code smells (e.g., `5min`, `1h30min`, `2d`; 1 day = 8 hours). Rules missing custom durations fall back to fixed defaults per severity level, ensuring deterministic calculations. |
| **Debt ratio** | Total technical debt divided by estimated development cost (calculated at 30 minutes per line of code). |
| **Maintainability rating** | Derived from the Debt Ratio: A ≤ 5%, B ≤ 10%, C ≤ 20%, D ≤ 50%, E > 50%. |
| **Duplicated lines density** | Ratio of duplicated lines over total non-comment lines of code (ncloc). |

Ratings reflect the worst individual finding rather than finding density; a single blocker severity bug overrides lower-priority issues. Maintainability is the sole exception, evaluating smell density relative to overall project size.

### Default gate profile

| Metric | Operator | Error threshold |
| --- | --- | --- |
| New coverage | `LESS_THAN` | 80.0% |
| New duplicated lines density | `GREATER_THAN` | 3.0% |
| New maintainability rating | `GREATER_THAN` | 1 (worse than A) |
| New reliability rating | `GREATER_THAN` | 1 (worse than A) |
| New security hotspots reviewed | `LESS_THAN` | 100.0% |

> **Minimum activation threshold** — Coverage and duplication gates execute only when a change contains at least **20 added or modified lines**, preventing minor patches from triggering failures on statistically insignificant sample sizes.

---

## 4. Rule identifiers

```
QG-<LANG>-<CAT>-<NNNN>

```

* **`<LANG>`** — `ALL` (multi-language), `SEC` (secrets, global), `CS` (C# / VB.NET), `JV` (Java), `JS` (JavaScript), `TS` (TypeScript), `PY` (Python), `PP` (PHP), `GO` (Go), `RB` (Ruby), `KT` (Kotlin), `SW` (Swift), `RS` (Rust), `DART` (Dart / Flutter), `CC` (C/C++), `SH` (Shell), `TF` (Terraform), `DK` (Dockerfile), `K8` (Kubernetes), `CF` (CloudFormation), `CSS` (CSS/SCSS/Sass/Less), `SQL`, `HTML`, `JSON`, `XML`, `RAZ` (Razor), `XAML`.
* **`<CAT>`** — `BUG` (correctness), `SEC` (security), `SML` (maintainability), `PRF` (performance), `CNV` (conventions/formatting).
* **`<NNNN>`** — Zero-padded sequential ID per `(LANG, CAT)`. Rule IDs are **never reused**, remaining retired if a rule is deprecated.

Category types map directly to issue kind and default severity: `SEC` → Vulnerability (Major+), `BUG` → Bug, `SML` / `CNV` / `PRF` → Code Smell.

---

## 5. Rules

The engine loads **3795 rules**, backed by **5861 catalog entries** (either implementing inline detection or documenting programmatic C# rules). Every rule provides an English title, output message, summary, explanation (*why is this an issue*), and remediation guide (*how to fix*).

### Languages

Files are detected by extension, tokenized, parsed, and analyzed. Structural depth dictates tree capabilities: dedicated parsers supply exact statement bounds, structural parsers map control flow/blocks, and configuration readers parse key-value hierarchies.

| Language | Code | Rules | Tree |
| --- | --- | --- | --- |
| Java | `JV` | 629 | dedicated parser |
| JavaScript | `JS` | 476 | dedicated parser |
| Python | `PY` | 486 | dedicated parser |
| C# / VB.NET | `CS` | 464 | dedicated parser |
| Kotlin | `KT` | 234 | dedicated parser (C-family dialect) |
| PHP | `PP` | 210 | dedicated parser |
| Terraform | `TF` | 148 | configuration tree |
| HTML | `HTML` | 140 | markup reader |
| Go | `GO` | 120 | dedicated parser |
| Dockerfile | `DK` | 120 | instruction list |
| Ruby | `RB` | 117 | structural parser |
| Kubernetes | `K8` | 117 | configuration tree |
| CSS / SCSS / Sass / Less | `CSS` | 120 | stylesheet reader |
| XML and descriptors | `XML` | 115 | markup reader |
| Swift | `SW` | 107 | structural parser |
| Dart / Flutter | `DART` | 100 | dedicated parser (C-family dialect) |
| CloudFormation | `CF` | 104 | configuration tree |
| JSON | `JSON` | 96 | configuration tree |
| Rust | `RS` | 57 | dedicated parser (C-family dialect) |
| Secrets (any language) | `SEC` | 31 | global token scanner |
| C / C++ | `CC` | 16 | structural parser |
| Shell | `SH` | 12 | structural parser |
| SQL | `SQL` | 9 | structural parser |
| TypeScript-specific | `TS` | 9 | dedicated parser |
| XAML / WPF / WinUI / Avalonia | `XAML` | 8 | markup reader linked to code-behind |
| Scala | `SC` | 16 | dedicated parser (C-family dialect) |
| Razor / Blazor | `RAZ` | 4 | combined C# `@code` parser and markup reader |
| Multi-language | `ALL` | 2 | active file tree model |

Extensions like TypeScript, Sass, SCSS, Less, JSX/TSX, and VB.NET inherit base rules from their parent language; listed rule counts represent dialect-specific additions.

### Razor and Blazor

Blazor components combine markup and partial classes across split files (e.g., `Counter.razor` and `Counter.razor.cs`). QualityGuard parses `@code` blocks as standard C# while reading surrounding tags as structured markup. Symbol tables merge across both files by component name, ensuring code-behind fields referenced solely within markup are correctly resolved as active symbols.

Four dedicated component rules handle framework-specific anti-patterns: unbindable query string types, non-public `[JSInvokable]` methods, unreachable query parameters on unrouted components, and inline lambda event handlers defined within markup loops.

### Frameworks

Framework-specific rules target structural API misuse across libraries:

* **Entity Framework** — Database queries executed within loops, unbatched single-item updates, in-memory filtering of unmaterialized queries, and synchronous database calls inside async call paths.
* **Dapper & ADO.NET** — Dynamic string concatenation inside SQL statements instead of parameterized commands.
* **HTTP Client** — Instantiating `HttpClient` per request, leading to socket exhaustion under load.
* **Blazor** — Unbindable query parameters, invalid JS interop targets, `async void` handlers capable of dropping the circuit, unmanaged event subscriptions, and inline handler allocation in loop iterations.
* **ASP.NET Core** — Controller endpoints rendering unused view infrastructure, absolute action routes breaking controller prefixes, missing base routes, template paths containing leading slashes, `[Pure]` methods returning `void`, overlapping `[Flags]` enum values, public custom exceptions, lock instances on `this` or `string` literals, unassigned `DateTime.Kind`, and `ToString` overloads returning `null`.
* **WPF, WinUI, Avalonia** — Duplicate resource keys, unresolved static resources, unbound event handlers, missing two-way binding paths, and hardcoded markup credentials.

Security rules scan infrastructure and application settings for un-salted/predictable hashes, weak AES cipher modes (ECB), static IVs, weak signing keys, exposed cloud storage buckets, public API endpoints missing authorization middleware, and unencrypted transport layers.

### The default profile

Stylistic rules, naming conventions, and metric limits are off by default in `Rules/DefaultProfile.cs` to reduce noise, running only when requested:

```bash
dotnet run --project src/QualityGuard.Cli -- --path ./src               # default profile
dotnet run --project src/QualityGuard.Cli -- --path ./src --all-rules   # includes conventions

```

All rules supply an English summary, flaw rationale, and remediation steps. Passing `--fix-hints` prints inline remediation tips directly to standard out.

### Rules as data

Simple rules use declarative YAML definitions in `src/QualityGuard.Core/Rules/Catalog/*.yaml`:

```yaml
- key: QG-PY-SEC-0055
  name: Encryption algorithms should use current cryptographic parameters
  languages: [py]
  category: SEC
  severity: critical
  message: ECB reveals the shape of the plaintext; use an authenticated mode such as GCM.
  summary: A block cipher is used in a mode that leaks structure.
  why: |
    ECB encrypts equal blocks to equal ciphertext, so patterns in the plaintext survive encryption.
  fix: |
    Use an authenticated mode (GCM, ChaCha20-Poly1305) and a fresh nonce for every message.
  detect:
    - member: [AES.MODE_ECB]
    - member: [modes.ECB]

```

Pattern matchers support invocation signatures, instantiation, accessors, string literals, line patterns, type bindings, and logical constraints (`argTainted`, `argDynamic`, `resultUnused`, `withoutArgs`, `requires`, `absent`). Complex rules requiring multi-file context use programmatic C# implementations against `SyntaxQuery`.

### Java and Python on the tree

AST analysis for Java and Python evaluates structural constructs rather than raw lines:

* **Java** — Contract compliance checks: `Iterator.next()` omitting `NoSuchElementException`, `wait()` calls outside synchronized loops, `Boolean`-returning methods returning `null`, threads spawned within constructors, `iterator()` returning `this`, zero-indexed JDBC accessors, `YYYY` week-year date format mismatches, and `compareTo` overloads. Code smells: instantiable static utility classes, redundant self-assignments, redundant `public` modifier keywords on interface members, double-brace initialization, `clone()` overrides, instance methods writing to static fields, empty statements, `finalize()` overrides, custom classes extending `Error`, jump labels inside switch cases, misspelled `toString`/`equals` overrides, methods named after their enclosing class, mutable `public static` fields, `hasNext()` side-effects advancing state, `BigDecimal` instantiated from `double`, swallowed exceptions in catch blocks, JDK internal package imports, and throwing signatures on `main`.
* **Python** — Execution bugs: mutable default arguments, raising literal strings, duplicate keyword parameters, `__exit__` methods re-raising exceptions, shadowed `except` blocks, constant conditional expressions, invalid `open()` modes, unhashable dictionary keys, `NaN` comparisons (`nan == nan`), values returned inside generators, and missing base classes on custom exceptions. Structural issues: `break` outside loops, `__init__` returning values, invalid identifiers in `__all__`, `for...else` constructs missing `break` statements, duplicate dictionary/set keys, tuple assertions (`assert (x, y)`), identity checks using `type()` instead of `isinstance()`, string slicing instead of `.startswith()`, lambdas bound to identifiers, nested ternaries, and single-handler catch blocks that only re-raise.

Rules were validated against real open-source codebases prior to inclusion: the Java analyzer suite (2700 files, 249k ncloc) and CPython's standard library (542 files, 213k ncloc).

### PHP on the tree

PHP is parsed via a dedicated C-family dialect parser, identifying dynamic variable names, legacy PHP 4 constructors, `$this` usage within static contexts, unreachable catch clauses, duplicate arguments in method calls, thrown string literals, dangling `foreach` references, duplicate constant definitions, and suppressed errors via `@`.

WordPress-specific rules analyze `wp-config.php` files for disabled auto-updates, enabled inline file editing (`DISALLOW_FILE_EDIT`), unauthenticated database repairs, and unrestricted external HTTP calls.

### C# and JavaScript on the tree

* **C#** — Type design checks: public fields, instantiable static classes, non-specific `Exception` throwing, obsolete attributes missing explanation strings, pass-through properties, empty finalizers, un-namespaced types, and methods returning constant literals. Logical errors: modulo arithmetic on negative integers (`x % 2 == 1`), `IndexOf(...) > 0` boundary errors (omitting index 0), `new Guid()` empty instantiations, throwing property getters, `protected` members inside `sealed` classes, and runtime-invoked methods (`Dispose`, `Equals`, `GetHashCode`, `ToString`) throwing exceptions. Additional checks enforce structural logging rules, cancellation token bindings, analyzer hints, and Azure Functions async patterns (`.Result`/`.Wait()` blocking calls).
* **JavaScript / TypeScript** — Flaws covered: string mutations assigned nowhere, invalid `typeof` comparison strings, `for-in` iterations over arrays, sparse array holes (elision), self-assignments, duplicate scope bindings, redundant union types, `new Function` usage, implicit object shorthand traps, `arguments` object usage, nested template strings, untyped `any` leaks, duplicate imports, and missing property getters. Checks also flag bitwise operator typos (`&` vs `&&`), explicit `undefined` assignments, prototype modifications, `indexOf(...) > 0` errors, array `sort()` missing comparator callbacks, and string instantiation (`new String()`).

Validated on the reference C# suite (1,405 files, 92k ncloc) and a 2,588-file TypeScript project (200k ncloc).

### Web front ends

Parsers evaluate structural relationships across markup and stylesheets:

* **CSS / SCSS / Sass / Less** — Duplicate property declarations, shorthand properties overriding longhands, empty rulesets, global `!important` abuse, duplicate selectors, missing generic font fallbacks, invalid `@import` ordering, deep selector nesting, and non-standard `z-index` scales.
* **HTML** — Missing doctype/title elements, disabled viewport zooming, skipped heading ranks, orphaned child tags (`<figcaption>`, `<li>`, `<dt>`), missing image `alt` attributes, unlinked control labels, invalid `tabindex` values, and un-sandboxed `target="_blank"` links.
* **JSON** — Duplicate keys, committed API keys/secrets, and unpinned wildcard dependency versions.

### Mobile: Dart and Flutter

Dart rules leverage the C-family AST driver, checking for `setState()` invocations during `build()`, mutable fields within `StatelessWidget` classes, un-disposed controllers/subscriptions, `async` methods lacking `await` operators, and invalid `BuildContext` usage across asynchronous gaps missing `mounted` guard checks.

### Mobile: Swift

Swift structural analysis flags force-unwrapping operators (`try!`, `as!`), main-thread blocking calls, swallowed error blocks, raw secret storage in `UserDefaults`, un-sanitized SQL string interpolation, unencrypted HTTP requests, and insecure hashing algorithms.

### Mobile: Kotlin and Android

Kotlin uses a dedicated C-family dialect parser supporting **224 rules**, covering Coroutine dispatchers, non-null assertions (`!!`), `SharedPreferences` crypto, Android security patterns, and idiomatic structural cleanups (`==` vs `equals()`, `any()` vs `find() != null`, array handling in data classes, public mutable state flows, and unpinned Gradle dependencies).

* **Intents and receivers** — Implicit un-permissioned broadcasts, sticky broadcasts, and dynamically registered receivers exposed to external apps.
* **WebViews** — Un-sanitized file/content access flags, JavaScript execution on untrusted domains, and native object bridge injections.
* **KeyStore & Security** — Unauthenticated KeyStore key creation, biometric prompts decoupled from crypto objects, hardcoded DB encryption keys, and static initialization vectors.
* **Build Profiles** — Debuggable production release builds, minification-disabled flags, and bypassed dependency verification in Gradle scripts.

### Secrets, in every language

Secret scanners run token pattern matching across all file types using anchored provider prefixes: AWS, Azure, GCP, Stripe, GitHub, GitLab, npm, private key blocks, database connection strings, Slack, Discord, and Telegram webhooks. Test mocks and documentation fixtures are filtered out automatically.

### Infrastructure as code

IaC files parse into key-value block structures to evaluate contextual safety:

* **Terraform (148 rules)** — Unencrypted storage resources, open inbound IP blocks (`0.0.0.0/0`), outdated TLS endpoints, missing access logs, wildcard IAM permissions (`*`), non-rotated keys, short backup retention, administrative role bindings (`Owner`/`Contributor`), un-purged Key Vaults, and compute workloads missing managed identity profiles across AWS, Azure, and Google Cloud.
* **CloudFormation (104 rules)** — Public S3 access configuration gaps, unauthenticated API Gateway routes, and missing automated snapshot settings.
* **Kubernetes (117 rules)** — Privileged containers, privilege escalation vectors, host namespace leakage (`hostPID`/`hostIPC`), root user execution, missing CPU/RAM resource limits, unpinned image tags, wildcard RBAC permissions, host ports, and remote exec access capabilities.
* **Dockerfile (120 rules)** — Unpinned base image tags, casing inconsistencies in instructions, relative `WORKDIR` paths, consecutive `RUN` statements, raw secrets in `ENV` arguments, and root container execution risks.

### Descriptors and platform configuration

* **Android Manifest** — Debuggable build flags, plain-text network traffic permissions, unencrypted backup flags, exported receiver components missing explicit permissions, and un-scoped content providers.
* **Java EE Descriptors** — Unmapped filter declarations, misconfigured container interceptors, and overlapping validation form names.
* **ASP.NET `web.config**` — Disabled custom error pages (exposing raw stack traces) and missing security headers (`X-Content-Type-Options`).
* **WordPress `wp-config.php**` — Enabled file editors (`DISALLOW_FILE_EDIT`), disabled automatic security updates, active database repair scripts, and un-filtered HTML rights.

### Security coverage

**639 security rules** explicitly cover Command Injection, SQL Injection, Path Traversal, Open Redirect, SSRF, Unsafe Deserialization, XXE, Dynamic Code Execution, Broken Cryptography, Permissive CORS, Missing Security Headers, IAM Escalation, and IaC Misconfigurations.

---

## 6. Scanning files and folders

Pass individual file paths or directories via `--path`. Directory traversal scans recursively down through all subfolders.

```bash
# Single file
dotnet run --project src/QualityGuard.Cli -- --path ./src/App/Program.cs

# Directory path with per-folder summaries
dotnet run --project src/QualityGuard.Cli -- --path ./src --by-folder

# Multiple targets, inclusion globs, and exclusions
dotnet run --project src/QualityGuard.Cli -- \
  --path ./src,./tests \
  --include "**/*.cs" \
  --exclude "**/Generated/**"

```

Ignored targets by default:

* Build and dependency artifacts: `bin`, `obj`, `build`, `dist`, `out`, `target`, `node_modules`, `vendor`, `venv`, `.git`, `.gradle`, `.terraform`, etc.
* Minified and generated files: `*.min.js`, `*.bundle.js`, `*.designer.cs`, `*.generated.*`, `*.pb.go`, `*.d.ts`.
* Files exceeding `--max-file-kb` (default: 2048 KB) or containing binary NUL bytes within the initial 512 bytes.

Pass `--all-files` to force scanning of ignored targets.

---

## 7. CLI

```bash
# Scan, custom gate evaluation, SARIF output
dotnet run --project src/QualityGuard.Cli -- \
  --path ./src --gate ./config/gate.json --sarif ./artifacts/report.sarif.json

# Evaluate Quality Gate over existing SARIF file
dotnet run --project src/QualityGuard.Cli -- \
  --sarif-in ./artifacts/input.sarif.json --gate ./config/gate.json

# Calculate new_* ratings based on current findings
dotnet run --project src/QualityGuard.Cli -- --path ./src --new-code

# Coverage integration against git diff
dotnet run --project src/QualityGuard.Cli -- \
  --path ./src --coverage ./artifacts/lcov.info --base origin/main

# Export HTML dashboard and Markdown summaries
dotnet run --project src/QualityGuard.Cli -- \
  --path ./src --html ./artifacts/report.html --markdown ./artifacts/report.md

```

| Option | Function |
| --- | --- |
| `--path <dir|file>` | Target path(s). Accepts comma-separated lists and repeatable flags. |
| `--include <glob>` | File path inclusion glob patterns. |
| `--exclude <glob>` | File path exclusion glob patterns. |
| `--all-files` | Forces scanning of build, dependency, and generated files. |
| `--max-file-kb <n>` | Maximum file size threshold in KB (default: 2048). |
| `--by-folder` | Prints per-directory summary of ncloc, bugs, vulnerabilities, and smells. |
| `--gate <json>` | Specifies a custom Quality Gate configuration JSON file. |
| `--sarif <out.json>` | Exports scan findings and gate outcomes to SARIF 2.1.0 format. |
| `--sarif-in <file>` | Reads metrics from an existing SARIF file without re-scanning code. |
| `--html <out.html>` | Writes a self-contained HTML report with embedded CSS, JS, and dataset. |
| `--markdown <out.md>` | Generates a Markdown formatted summary report. |
| `--new-code` | Maps findings directly to `new_*` metric ratings before evaluating gate gates. |
| `--coverage <file>` | Reads code coverage files (LCOV, Cobertura, JaCoCo). Merges multi-shard inputs. |
| `--base <ref>` | Specifies base branch, tag, commit, or date (`yyyy-MM-dd`) for delta comparison. |
| `--fix-hints` | Prints remediation guidance beneath reported issues in CLI output. |
| `--verbose` | Output detailed file metrics, skipped file reasons, and taint flow chains. |
| `--rules` | Lists loaded engine rules alongside rule metadata. |
| `--dump-ast` | Prints raw syntax tree structure for a specified file. |

### Exported reports

Reports render identically across formats. `--html` produces a single standalone dashboard file containing inline styles and data tables. `--markdown` outputs structured text suitable for pull request comments or automated pipeline summaries.

### Coverage exclusions

Source code coverage exclusions defined directly within codebases are recognized and excluded from final metric metrics:

| Marker / Attribute | Target Languages |
| --- | --- |
| `[ExcludeFromCodeCoverage]`, `[GeneratedCode(...)]` | C# |
| `@Generated` | Java, Kotlin |
| `# pragma: no cover` | Python |
| `/* istanbul ignore next */`, `/* istanbul ignore file */` | JavaScript, TypeScript |
| `# :nocov:` ... `# :nocov:` | Ruby |
| `/** @codeCoverageIgnore */` | PHP |
| `// LCOV_EXCL_LINE`, `// LCOV_EXCL_START`, `// coverage:ignore-line` | Universal (all supported languages) |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | `PASSED` — Quality Gate passed all criteria. |
| `1` | `FAILED` — One or more Quality Gate conditions failed. |
| `2` | `ERROR` — Runtime failure, invalid flags, or missing target files. |

### Example CLI output

```
QUALITY GATE: Passed
  [OK  ] new_coverage: N/A vs 80.0 (LessThan) - passed
  ISSUE QG-CS-SEC-0018 Critical: Validate the path to prevent path traversal. (src/DocumentService.cs:10)
      flow  line 7: 'ReadRequestedFile' returns data that enters the program in RequestReader.cs
      flow  line 10: tainted value reaches this sink

SUMMARY  153 files, 78940 ncloc, 18556 complexity, 1.9% duplicated
  Bugs                42   reliability C   major 41, minor 1
  Vulnerabilities     56   security    D   critical 13, major 43
  Security hotspots    0   reviewed    100%
  Code smells       1301   maintainability A   critical 220, major 293, minor 788
  Technical debt   38.4d   ratio 0.78%
  Most frequent rules:
    QG-ALL-SML-0005   219  'ParseBraces' scores 21 on nesting-aware complexity (limit is 15)

FOLDER                                             FILES   NCLOC  BUGS  VULN SMELLS
src/QualityGuard.Core/Analysis                        13    1715     7     3    125
src/QualityGuard.Core/Rules/Languages                 38   19496    13    44    511
src/QualityGuard.Core/Semantics                        3     425     1     0     21

```

---

## 8. Quality bar

Rules undergo validation against open-source repositories and internal production codebases. Noisy rules are refactored or removed, and fixed false positives are recorded as unit regression tests (**721 automated tests** currently cover AST drivers, taint flow, and scanner logic).

### Noise metrics per language

Noise levels are measured using open-source projects alongside real-world legacy production codebases:

| Project | Language | ncloc | Findings | Per 1k lines |
| --- | --- | --- | --- | --- |
| CloudFormation templates library | CloudFormation | 26 214 | 10 | **0.4** |
| Google Cloud Terraform modules | Terraform | 50 085 | 90 | **1.8** |
| AWS Terraform modules | Terraform | 5 475 | 22 | **4.0** |
| Public Terraform module collections | Terraform | 55 560 | 112 | **2.0** |
| Azure Terraform library | Terraform | 22 146 | 193 | **8.7** |
| Kubernetes example manifests | Kubernetes | 5 743 | 142 | **24.7** |
| express | JavaScript | 14 707 | 56 | **3.8** |
| rails | Ruby | 281 755 | 1 343 | **4.8** |
| guzzle | PHP | 48 147 | 378 | **7.9** |
| gson | Java | 47 559 | 462 | **9.7** |
| okio | Kotlin | 44 514 | 601 | **13.5** |
| ripgrep | Rust | 42 211 | 633 | **15.0** |
| Alamofire | Swift | 26 592 | 369 | **13.9** |
| cobra, gin | Go | 30 723 | 488 | **15.9** |
| Blazor Enterprise App | C# | 58 468 | 876 | **15.0** |
| axios, nest | TypeScript | 36 073 | 648 | **18.0** |
| Newtonsoft.Json | C# | 126 652 | 2 647 | **20.9** |
| flask | Python | 13 303 | 200 | **15.0** |
| WebForms Enterprise Legacy (2010) | C# | 152 633 | 8 522 | **55.8** |
| scalaz | Scala | 48 758 | 103 | **2.1** |

### False positive analysis

Sample evaluations on open-source codebases (e.g., `gson`) reduced false positive occurrences from **12 of 24** down to **2 of 18** without losing true positives by addressing parser edge cases (such as handling contextual keywords like `in` across mixed Java/C# rules).

### Annotated corpus evaluation

| Corpus | Annotated files | Marked lines | Lines reported |
| --- | --- | --- | --- |
| Java | 1 022 | 10 320 | **46.3%** |
| Python | 590 | 6 427 | **41.1%** |

Calculated via `tools/compare_expectations.py`. Unannotated findings represent valid secondary issues detected outside the original test harness annotations.

### Reference analyzer benchmark comparison

Benchmarking against official language platform analyzer suites yields recall and precision metrics across third-party test sets:

| Corpus | Annotated files | Expected lines | Recall | Precision |
| --- | --- | --- | --- | --- |
| C# | 1,079 | 11,238 | **64.3%** | 39.3% |
| Go | 52 | 234 | **69.2%** | 47.7% |
| JavaScript | 109 | 921 | **53.2%** | **50.8%** |
| Python | 611 | 6,451 | **51.4%** | 40.6% |
| Kotlin | 159 | 2,030 | **53.3%** | 49.8% |
| Java | 1,004 | 10,130 | **46.0%** | 36.7% |
| PHP | 285 | 2,482 | **44.3%** | 47.3% |
| VB.NET | 254 | 2,392 | **40.4%** | **64.5%** |

### Implementation distribution

| Implementation Type | Rule Count | Output Share on Production Code |
| --- | --- | --- |
| Syntax tree, semantic model, taint flow | 276 | 55% |
| Token scanning heuristics | 409 |  |
| Line-based regex scanning | 60 | **45%** |
| Catalogue regex pattern entry | 181 |  |

Heuristic checks are continuously migrated to AST-based queries to eliminate false positives caused by generic string matching, contextual misidentifications, and statement boundary errors.

### Direct Roslyn analyzer side-by-side comparison (.NET)

Evaluating standard Roslyn static rules against QualityGuard over production codebases:

| Metric | Reference Analyzer | QualityGuard |
| --- | --- | --- |
| Findings | 132 | 434 |
| Distinct lines flagged | 124 | 405 |
| Files touched | 36 | 70 |
| Distinct rules triggered | 36 | 69 |

QualityGuard flags **95% of lines identified by Roslyn rules** (within a 1-line window tolerance), while expanding detection coverage across additional code smells, structural issues, and unmanaged patterns.

---

## 9. Non-goals

* **No database or SQL persistence** — Strictly operates in-memory.
* **No web UI or hosted dashboard** — Outputs purely via CLI and SARIF files.
* **No background daemon process** — Runs as an ephemeral CI execution tool.
* **No built-in user management or SSO integration**.
* **No mandatory cloud service dependencies**.
