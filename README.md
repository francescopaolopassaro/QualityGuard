# ⚖️ QualityGuard

<img width="1197" height="766" alt="qualityguard_splash" src="https://github.com/francescopaolopassaro/QualityGuard/blob/main/imgs/qualityguard.svg" />

**QualityGuard** is a stateless, in-memory code quality engine written in C# for continuous integration pipelines. It parses source code, computes metrics, runs static analysis rules, evaluates a configurable Quality Gate, and exits with `PASSED` or `FAILED` — no background service, database, or UI required.

```bash
dotnet tool install -g QualityGuard.Tool
qualityguard --path ./src --by-folder
```

No clone, no build: install it as a .NET tool or pull the Docker image (§8).

No install at all (like `npx`), on any OS with the .NET 10 SDK:

```bash
dnx QualityGuard.Tool --yes -- --path ./src      # CLI, one-shot
dnx QualityGuard.Mcp --yes                        # MCP server over stdio
```

The MCP server is also a .NET tool: `dotnet tool install -g QualityGuard.Mcp`, then run `qualityguard-mcp`. Docker is optional.

It packs **4095 rules across 27 languages** (including **665 security rules**), executing on real syntax trees with a semantic model, project index, and interprocedural taint analysis. Coverage extends beyond core languages to cloud infrastructure (AWS, Azure, and Google Cloud via Terraform and CloudFormation), Kubernetes manifests, Dockerfiles, Android manifests, Gradle scripts, Java EE and ASP.NET descriptors, WordPress configurations, and .NET frameworks (Entity Framework, Dapper, ASP.NET Core, Blazor, MAUI, WPF, WinUI, and Avalonia).

Rules ship in a **default profile** — convention and stylistic checks stay disabled until explicitly requested with `--all-rules`, preventing noisy reports from masking critical defects.

Engine engineering prioritizes precision: rules are vetted on third-party production codebases before inclusion, noisy checks are rewritten on the syntax tree or dropped, and fixed false positives are locked in place with regression tests (§9).

### Security is organized around the OWASP

Every security rule carries its OWASP category and CWE identifier, so CLI reports and SARIF exports
group findings by the standard your auditors speak. Injection-style rules run through the data-flow
engine: they fire only when untrusted input actually reaches the sink, which keeps framework code quiet.

Security coverage spans all ten OWASP Top 10 categories with dedicated detection:

| Category | Coverage |
| --- | --- |
| A01 Broken Access Control | Path traversal, open redirects, access control gaps |
| A02 Cryptographic Failures | Weak hashing, predictable randomness, TLS validation |
| A03 Injection | SQL, command, XPath, eval, code generation — all taint-gated |
| A04 Insecure Design | Debug mode exposure in production servers |
| A05 Security Misconfiguration | CORS wildcards, cookie flags, framework debug settings |
| A06 Vulnerable Components | Hard-coded dependency versions, outdated base types |
| A07 Auth Failures | Plain-text password comparisons, timing attacks |
| A08 Integrity Failures | Unsafe deserialization of untrusted formats |
| A09 Logging Failures | Log injection through untrusted newlines, error detail exposure |
| A10 SSRF | Server-side request forgery via outbound URL manipulation |

Detection is scored continuously against the intentionally vulnerable **OWASP Benchmark** corpus -
recall and false-positive rate on those 2,740 Java cases guide every release. The engine also ships a
**multi-language semantic model**: sources (request parameters, form bodies, environment variables),
sanitizers (OWASP encoders, framework validators), and sinks are recognized across ASP.NET Core,
Spring, Flask, Django, Express and Go net/http, so the same injection rule speaks the language of
every framework it scans.

---

## 1. Packages

| Project | Responsibility |
| --- | --- |
| `QualityGuard.Core` | Domain models, tokenizers, parsers, semantic model, taint analysis, duplication engine, rule framework, and gate evaluator. |
| `QualityGuard.Sources.Sarif` | Reader and writer for **SARIF 2.1.0**: imports external metrics, exports findings and gate verdicts. |
| `QualityGuard.Cli` | Pipeline entry point executable with explicit exit codes. |
| `QualityGuard.Mcp` | **Model Context Protocol server** (`net10.0`): exposes scans, gate state, and AI-formatted Markdown reports over stdio or Streamable HTTP for local agents (Claude Code, OpenCode, Codex, Copilot). |

All four projects ship as NuGet packages (`1.0.8`). The CLI is also published as the **`QualityGuard.Tool`** package, the ready-to-install `qualityguard` .NET tool (`dotnet tool install -g QualityGuard.Tool`), while `QualityGuard.Cli` stays a plain library package. The MCP server consumes the core packages from NuGet and operates fully standalone.

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
qualityguard --path ./src               # default profile
qualityguard --path ./src --all-rules   # includes conventions

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

`--path` takes a file or a folder. A folder is scanned **with all its subfolders**, and you can pass several targets, either repeating the flag or separating them with commas.

```bash
# One file
qualityguard --path ./src/App/Program.cs

# A whole folder, with a summary for each directory
qualityguard --path ./src --by-folder

# Several folders, only C# files, skipping generated code
qualityguard --path ./src,./tests --include "**/*.cs" --exclude "**/Generated/**"
```

What is left out by default, so the report talks about *your* code:

* Build and dependency folders: `bin`, `obj`, `build`, `dist`, `out`, `target`, `node_modules`, `vendor`, `venv`, `.git`, `.gradle`, `.terraform`, and similar.
* Minified and generated files: `*.min.js`, `*.bundle.js`, `*.designer.cs`, `*.generated.*`, `*.pb.go`, `*.d.ts`.
* Files larger than `--max-file-kb` (2048 KB by default) and binary files.

Pass `--all-files` when you really want those scanned too. If a path does not exist the run stops with exit code `2`, so a typo can never turn into a green build.

---

## 7. Command line (CLI)

This is the everyday way to use QualityGuard: one command that scans your code, applies a Quality Gate and tells you (and your pipeline) whether the build is acceptable.

### Install

```bash
dotnet tool install -g QualityGuard.Tool      # once per machine
qualityguard --path ./src                     # from now on
```

| You have | Do this |
| --- | --- |
| .NET 9 SDK or later | `dotnet tool install -g QualityGuard.Tool` (the tool targets .NET 9 and .NET 10) |
| .NET 10 SDK, and you do not want to install anything | `dnx QualityGuard.Tool --yes -- --path ./src` |
| .NET SDK, and you want the version pinned in the repository | a local tool: `dotnet new tool-manifest`, then `dotnet tool install QualityGuard.Tool` (see §8) |
| No .NET at all | the ready-made `qualityguard.exe` from GitHub Releases (Windows, Linux, macOS), the Docker image, or the self-contained binary (see §8) |

It runs on Windows, Linux and macOS. Update with `dotnet tool update -g QualityGuard.Tool`.

### Install scope

A .NET tool can be installed at three levels. Pick the one that matches who must get the same version.

| Scope | Command | Available to |
| --- | --- | --- |
| **Global** (per user) | `dotnet tool install -g QualityGuard.Tool` | Every folder, for your user account. |
| **Local** (per repository) | `dotnet new tool-manifest` then `dotnet tool install QualityGuard.Tool` | Whoever clones the repository: the version is pinned in `.config/dotnet-tools.json`, and `dotnet tool restore` installs it. Run it as `dotnet qualityguard`. |
| **Tool path** (per folder) | `dotnet tool install QualityGuard.Tool --tool-path ./tools` | Only that folder, with no change to your user profile. Handy for CI agents and containers. |

Add `--version 1.0.8` to pin a version. For a team, prefer the local scope: everybody and the pipeline run the same QualityGuard.

### Your first scan

```bash
qualityguard --path ./src
```

You get the Quality Gate verdict, the issues found (each with file and line), and a `SUMMARY` block with bugs, vulnerabilities, security hotspots, code smells, technical debt and an A–E rating for reliability, security and maintainability. Nothing is written to disk and no network is used: it is read-only.

To see *how to fix* each issue and to include the convention and style rules that are off by default:

```bash
qualityguard --path ./src --fix-hints --all-rules
```

### Usage examples

```bash
# 1. Quick look at a project, broken down by folder
qualityguard --path ./src --by-folder

# 2. Fail the build when your own gate is not met
qualityguard --path ./src --gate ./gate.json

# 3. Produce reports to share (SARIF for code scanning, HTML and Markdown for people)
qualityguard --path ./src --gate ./gate.json   --sarif ./out/report.sarif.json --html ./out/report.html --markdown ./out/report.md

# 4. Judge only what changed against main, with test coverage
qualityguard --path ./src --new-code --coverage ./out/lcov.info --base origin/main

# 5. Re-check an existing SARIF report with a stricter gate, without scanning again
qualityguard --sarif-in ./out/report.sarif.json --gate ./gate.strict.json

# 6. Several folders, one language, no generated code
qualityguard --path ./src,./tests --include "**/*.cs" --exclude "**/Generated/**"

# 7. Mark folders as third-party code, so they are scanned but not blamed on you
qualityguard --path . --vendor ./ThirdParty

# 8. Understand the syntax tree of a file (useful when reporting a false positive)
qualityguard --path ./src/App/Program.cs --dump-ast

# 9. See every rule that is loaded
qualityguard --rules
```

PowerShell users: write the examples on one line, or continue lines with a backtick `` ` `` instead of `\`.

### Options

| Option | What it does |
| --- | --- |
| `--path <dir\|file>` | What to scan. Repeatable, or a comma-separated list. |
| `--include <glob>` | Scan only files matching the pattern (alias `--only`). |
| `--exclude <glob>` | Skip files matching the pattern (alias `--ignore`). |
| `--all-files` | Also scan build, dependency and generated files (alias `--no-default-excludes`). |
| `--max-file-kb <n>` | Skip files larger than this size in KB (default 2048). |
| `--by-folder` | Adds a per-directory table: files, lines of code, bugs, vulnerabilities, smells. |
| `--gate <json>` | Your Quality Gate definition (alias `--config`). Without it, the default gate applies. |
| `--sarif <file>` | Writes the findings and the gate result as SARIF 2.1.0 (alias `--sarif-out`). |
| `--sarif-in <file>` | Evaluates the gate on an existing SARIF report instead of scanning. |
| `--html <file>` | Writes a single self-contained HTML report. |
| `--markdown <file>` | Writes a Markdown report, ready for a pull request comment (alias `--md`). |
| `--new-code` | Computes the `new_*` ratings, so the gate looks at recent changes only. |
| `--base <ref>` | What "new" means: a branch, tag, commit or date (`yyyy-MM-dd`) (alias `--diff-base`). |
| `--coverage <file>` | Reads coverage (LCOV, Cobertura, JaCoCo) and merges several files. |
| `--all-rules` | Also runs the convention and style rules, off by default (alias `--every-rule`). |
| `--fix-hints` | Prints how to fix each issue under it (alias `--how-to-fix`). |
| `--vendor <path>` | Treats a path as third-party code (alias `--third-party`). |
| `--verbose` | Per-file metrics, skipped files and the full taint flow of each finding. |
| `--rules` | Lists the loaded rules with their metadata. |
| `--dump-ast` | Prints the syntax tree of the given file. |

### Install the MCP server in an AI agent

The MCP server (`QualityGuard.Mcp`) is a .NET tool too. Install it once, then register it with your agent. In Claude Code the registration has three scopes:

| Scope | Command | Who gets it |
| --- | --- | --- |
| `local` (default) | `claude mcp add qualityguard -- qualityguard-mcp` | You, in the current project only. |
| `project` | `claude mcp add --scope project qualityguard -- qualityguard-mcp` | Everybody on the project: it is saved in the `.mcp.json` file you commit. |
| `user` | `claude mcp add --scope user qualityguard -- qualityguard-mcp` | You, in every project. |

```bash
dotnet tool install -g QualityGuard.Mcp
claude mcp add --scope user qualityguard -- qualityguard-mcp
```

Without installing anything (needs the .NET 10 SDK): `claude mcp add --scope user qualityguard -- dnx QualityGuard.Mcp --yes`.

Other agents (OpenCode, Codex, Copilot) take the same command, `qualityguard-mcp` over stdio, in their own MCP configuration file.

### Exit codes

Your pipeline reads the result from the exit code, so you do not have to parse the output.

| Code | Meaning | What to do |
| --- | --- | --- |
| `0` | `PASSED`: the gate is satisfied. | Nothing, the build continues. |
| `1` | `FAILED`: at least one gate condition is not met. | Read the lines marked `[FAIL]` in the output: they say which condition and by how much. |
| `2` | `ERROR`: bad option, missing path, unreadable file. | Fix the command; this is not a quality verdict. |

```bash
qualityguard --path ./src --gate ./gate.json
case $? in
  0) echo "Quality gate passed" ;;
  1) echo "Quality gate failed" ; exit 1 ;;
  *) echo "QualityGuard could not run" ; exit 2 ;;
esac
```

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

## 8. Using QualityGuard in CI

The CLI is meant to run in a pipeline and decide the build with its exit code (`0` pass, `1` gate failed, `2` error). There are three ways to get it **without compiling the repository on every run**.

| Option | Needs on the runner | Best for |
| --- | --- | --- |
| **.NET tool** (`dotnet tool install`) | .NET 9 SDK or runtime | Runners that already have .NET |
| **Docker image** | Docker | Any runner, any language stack, reproducible versions |
| **Self-contained binary** (GitHub Releases, `qualityguard.exe`) | nothing | Locked-down or minimal runners |

### Option 1: .NET tool

```bash
dotnet tool install -g QualityGuard.Tool --version 1.0.8
qualityguard --path ./src --gate ./gate.json --sarif ./report.sarif.json
```

Install it as a local tool so the version is pinned in the repository:

```bash
dotnet new tool-manifest
dotnet tool install QualityGuard.Tool --version 1.0.8
dotnet tool restore          # in CI
dotnet qualityguard --path ./src
```

### Option 2: Docker image

The image is published on Docker Hub as [`digitalsolutionsdotit/qualityguard`](https://hub.docker.com/r/digitalsolutionsdotit/qualityguard) (tags `1.0.6` and `latest`):

```bash
docker pull digitalsolutionsdotit/qualityguard:1.0.6
```

#### Requirements

| Requirement | Detail |
| --- | --- |
| Docker | Docker Engine 20.10 or later (Docker Desktop works too). |
| Container type | Linux containers. Windows containers are not supported. |
| Architecture | `linux/amd64`. No ARM image is published. |
| Network | Access to Docker Hub to pull the image (it is public, no login needed). The scan itself uses no network. |
| Software on the runner | None: the .NET 9 runtime and the CLI are inside the image. |
| Code to analyse | Mounted on `/src` in the container (`-v "$PWD:/src"`). |
| Permissions | The mounted folder must be writable when you ask for reports (`--sarif`, `--html`, `--markdown`). |

#### Understanding `docker run`

```bash
docker run --rm -v "$PWD:/src" digitalsolutionsdotit/qualityguard:1.0.6 --path /src
```

| Part | What it does |
| --- | --- |
| `docker run` | Starts a container from an image. |
| `--rm` | Deletes the container when it exits, so no stopped container is left behind after each run. |
| `-v "$PWD:/src"` | Maps the current folder of your machine (`$PWD`) to `/src` inside the container. The container sees your code, and the reports it writes stay on your machine. |
| `digitalsolutionsdotit/qualityguard:1.0.6` | The image to run, with its version. Docker pulls it from Docker Hub if it is not local. |
| `--path /src` | Everything **after** the image name is passed to QualityGuard. Here it tells it which folder to analyse: the one you mapped. |

Options before the image name (`--rm`, `-v`) belong to Docker; options after it (`--path`, `--gate`, `--sarif`) belong to QualityGuard.

With more options:

```bash
docker run --rm -v "$PWD:/src" digitalsolutionsdotit/qualityguard:1.0.6 \
  --path /src/src \
  --gate /src/gate.json \
  --sarif /src/report.sarif.json \
  --html /src/report.html
```

* The trailing `\` only continues the command on the next line (use a backtick `` ` `` in PowerShell).
* Paths after the image name are **inside the container**: `/src/gate.json` is the `gate.json` file of your current folder.
* `report.sarif.json` and `report.html` appear in your current folder.

Per-shell notes:

* **Linux and macOS:** `$PWD` works as is.
* **PowerShell:** use `${PWD}`, i.e. `-v "${PWD}:/src"`.
* **Windows Command Prompt:** use `%cd%`, i.e. `-v "%cd%:/src"`.
* **Git Bash on Windows:** it may rewrite paths starting with `/`; set `MSYS_NO_PATHCONV=1` first.

The command prints the verdict and the summary, and the exit code tells the pipeline what happened: `0` passed, `1` gate failed, `2` error (for example a path that does not exist). Read it right after the run with `echo $?`.

Reports are written as root by default. To get files owned by your user, add `--user "$(id -u):$(id -g)"` before the image name. In CI, pin the version tag (`:1.0.6`) instead of `latest`.

#### Examples

The image has the CLI as entry point and `/src` as working directory: mount the repository there and pass the usual options.

```bash
docker run --rm -v "$PWD:/src" digitalsolutionsdotit/qualityguard:1.0.6 --path /src --by-folder
docker run --rm -v "$PWD:/src" digitalsolutionsdotit/qualityguard:1.0.6 --path /src --gate /src/gate.json --sarif /src/report.sarif.json
docker run --rm -v "$PWD:/src" digitalsolutionsdotit/qualityguard:1.0.6 --path /src --html /src/report.html --markdown /src/report.md
```

Build it yourself from the repository root:

```bash
docker build -t qualityguard .
docker run --rm -v "$PWD:/src" qualityguard --path /src
```

### Option 3: self-contained binary

**Ready-made download (no .NET needed):** every GitHub release carries a zip per platform, built by the `release-binaries` workflow: `win-x64`, `linux-x64` and `osx-arm64`. Download it from the [Releases page](https://github.com/francescopaolopassaro/QualityGuard/releases) and unzip: the archive holds a single file, `qualityguard.exe` on Windows and `qualityguard` elsewhere.

On Windows, put the folder on your `PATH` once and use it like any other command:

```powershell
Expand-Archive qualityguard-v1.0.8-win-x64.zip -DestinationPath C:\Tools\qualityguard
setx PATH "$env:PATH;C:\Tools\qualityguard"     # then open a new terminal
qualityguard --path .\src
```

To build it yourself:

```bash
dotnet publish src/QualityGuard.Cli -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o dist
./dist/QualityGuard.Cli --path ./src
```

Attach the result to a release or to a pipeline artifact and download it in the jobs that need it.

### GitHub Actions

Docker image, fails the job when the gate fails and uploads the reports:

```yaml
name: quality
on: [pull_request]
jobs:
  qualityguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan
        run: |
          docker run --rm -v "$PWD:/src" digitalsolutionsdotit/qualityguard:1.0.6 \
            --path /src --gate /src/gate.json \
            --sarif /src/report.sarif.json --markdown /src/report.md
      - name: Summary
        if: always()
        run: cat report.md >> "$GITHUB_STEP_SUMMARY"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: qualityguard
          path: |
            report.sarif.json
            report.md
```

.NET tool with the NuGet cache, SARIF uploaded to GitHub code scanning:

```yaml
jobs:
  qualityguard:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 9.0.x
      - uses: actions/cache@v4
        with:
          path: ~/.nuget/packages
          key: qg-tool-1.0.8
      - run: dotnet tool install -g QualityGuard.Tool --version 1.0.8
      - run: qualityguard --path src --sarif report.sarif.json
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif.json
```

Pull requests only: compare against the target branch and merge coverage (`fetch-depth: 0` is required for `--base`):

```yaml
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: qualityguard --path src --new-code --base origin/${{ github.base_ref }} --coverage coverage/lcov.info
```

### Azure DevOps

```yaml
steps:
  - task: UseDotNet@2
    inputs: { version: 9.0.x }
  - script: |
      dotnet tool install -g QualityGuard.Tool --version 1.0.8
      qualityguard --path $(Build.SourcesDirectory)/src --gate gate.json --sarif $(Build.ArtifactStagingDirectory)/report.sarif.json
    displayName: QualityGuard
  - task: PublishBuildArtifacts@1
    condition: always()
    inputs: { PathtoPublish: $(Build.ArtifactStagingDirectory), ArtifactName: qualityguard }
```

With Docker:

```yaml
  - script: docker run --rm -v "$(Build.SourcesDirectory):/src" digitalsolutionsdotit/qualityguard:1.0.6 --path /src --gate /src/gate.json
    displayName: QualityGuard
```

### GitLab CI

```yaml
qualityguard:
  stage: test
  image:
    name: digitalsolutionsdotit/qualityguard:1.0.6
    entrypoint: [""]
  script:
    - dotnet /opt/qualityguard/QualityGuard.Cli.dll --path . --gate gate.json --sarif report.sarif.json --html report.html
  artifacts:
    when: always
    paths: [report.sarif.json, report.html]
```

### Jenkins

```groovy
stage('QualityGuard') {
  agent { docker { image 'digitalsolutionsdotit/qualityguard:1.0.6'; args '--entrypoint=' } }
  steps {
    sh 'dotnet /opt/qualityguard/QualityGuard.Cli.dll --path . --gate gate.json --html report.html'
    archiveArtifacts artifacts: 'report.html', allowEmptyArchive: true
  }
}
```

### Bitbucket Pipelines, CircleCI, any shell

```yaml
# bitbucket-pipelines.yml
pipelines:
  default:
    - step:
        image: digitalsolutionsdotit/qualityguard:1.0.6
        script:
          - dotnet /opt/qualityguard/QualityGuard.Cli.dll --path . --gate gate.json
```

```yaml
# .circleci/config.yml
jobs:
  qualityguard:
    docker: [{ image: digitalsolutionsdotit/qualityguard:1.0.6 }]
    steps:
      - checkout
      - run: dotnet /opt/qualityguard/QualityGuard.Cli.dll --path . --gate gate.json
```

### Common recipes

```bash
# Fail only on the gate you define
qualityguard --path src --gate gate.json

# Scan several folders, keep the noise down
qualityguard --path src,tests --include "**/*.cs" --exclude "**/Generated/**"

# Include convention rules and print how to fix each issue
qualityguard --path src --all-rules --fix-hints

# Security-only pass on infrastructure code
qualityguard --path infra --include "**/*.tf" --include "**/*.yaml" --include "**/Dockerfile"

# Re-evaluate a stored report with a stricter gate, no re-scan
qualityguard --sarif-in report.sarif.json --gate gate.strict.json

# Use the exit code explicitly
qualityguard --path src --gate gate.json; code=$?
if [ "$code" -eq 1 ]; then echo "Quality gate failed"; elif [ "$code" -eq 2 ]; then echo "Tool error"; fi
exit $code
```

A minimal `gate.json` that blocks on the worst ratings:

```json
{
  "conditions": [
    { "metricKey": "new_reliability_rating",     "operator": "GREATER_THAN", "threshold": 1 },
    { "metricKey": "new_security_rating",        "operator": "GREATER_THAN", "threshold": 1 },
    { "metricKey": "new_maintainability_rating", "operator": "GREATER_THAN", "threshold": 1 }
  ]
}
```

> The snippets use the public image `digitalsolutionsdotit/qualityguard:1.0.6`. Pin a version tag in CI rather than `latest`.

---

## 9. Quality bar

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

## 10. Non-goals

* **No database or SQL persistence** — Strictly operates in-memory.
* **No web UI or hosted dashboard** — Outputs purely via CLI and SARIF files.
* **No background daemon process** — Runs as an ephemeral CI execution tool.
* **No built-in user management or SSO integration**.
* **No mandatory cloud service dependencies**.
