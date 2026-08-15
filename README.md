# QualityGuard

**QualityGuard** is a stateless, in-memory code quality engine written in C# for continuous
integration pipelines. It parses source code, computes metrics, runs static analysis rules, evaluates
a configurable Quality Gate and exits with `PASSED` or `FAILED` — no server, no database, no UI.

```bash
dotnet run --project src/QualityGuard.Cli -- --path ./src --by-folder
```

---

## 1. Packages

| Project | Responsibility |
| --- | --- |
| `QualityGuard.Core` | Domain models, tokenizers, parsers, semantic model, taint analysis, duplication detection, rule framework and gate evaluator. |
| `QualityGuard.Sources.Sarif` | Reader and writer for **SARIF 2.1.0**: imports metrics from an existing report, exports findings and gate state. |
| `QualityGuard.Cli` | Executable entry point for pipeline jobs; explicit exit codes. |

---

## 2. Analysis pipeline

Per file:

```
tokenize → syntax tree → semantic model → taint → metrics
```

Then across the whole scan:

```
project index → type resolution → interprocedural taint → rules → quality gate
```

* **Syntax tree** — recursive-descent parsers for C#, Java, Go, JavaScript and TypeScript (one
  C-family parser with dialects) and an indentation-driven parser for Python. Other languages fall
  back to a generic structural parser; `SyntaxTree.HasDedicatedParser` tells a rule whether the tree
  is exact enough to reason about statements.
* **Semantic model** — scopes, symbols and usages. Declarations, assignments and reads are linked, so
  a rule works on "this symbol" rather than "this name".
* **Project index** — types, base types, members, return types and reference counts across every
  scanned file, which is what makes cross-file rules possible.
* **Type resolution** — best-effort type of an expression. It answers `null` for "cannot tell", and
  rules must stay silent on that rather than guess.
* **Taint analysis** — sources (request data, environment, argv, superglobals), propagation through
  assignments and calls, sanitizers, and sinks. It runs **interprocedurally**: a function returning
  untrusted data becomes a source for every caller in any file, and a tainted argument taints the
  matching parameter of the callee wherever it is declared. Findings carry the source-to-sink flow.
* **Duplication** — lexical tokenization plus sliding-window hashing, no compilation required.

---

## 3. Domain model

* **`Metric` / `CoreMetrics`** — measures collected per file and aggregated per scan. The gate profile
  is centred on new code: `new_coverage`, `new_duplicated_lines_density`, `new_security_rating`,
  `new_reliability_rating`, `new_maintainability_rating`, `new_security_hotspots_reviewed`.
* **`Condition`** — one gate rule: `metricKey`, `operator` (`LESS_THAN`, `GREATER_THAN`) and a numeric
  `threshold`.
* **`QualityGateResult`** — global status plus the per-condition outcome and message.
* **`Severity`** — `BLOCKER`, `CRITICAL`, `MAJOR`, `MINOR`, `INFO`.
* **Issue kinds** — `Bug`, `Vulnerability`, `SecurityHotspot`, `CodeSmell`.
* **Technical debt** — remediation effort attached to every finding.

### Evaluation

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────────────┐
│  MetricReader   │ ---> │    Evaluator     │ ---> │    StatusCalculator     │
│ (Reads metrics) │      │(Evaluates rules) │      │ (Outputs PASSED/FAILED) │
└─────────────────┘      └──────────────────┘      └─────────────────────────┘
```

If **at least one** condition fails, the gate is `FAILED`.

### Default gate profile

| Metric | Operator | Error threshold |
| --- | --- | --- |
| New coverage | `LESS_THAN` | 80.0 % |
| New duplicated lines density | `GREATER_THAN` | 3.0 % |
| New maintainability rating | `GREATER_THAN` | 1 (worse than A) |
| New reliability rating | `GREATER_THAN` | 1 (worse than A) |
| New security hotspots reviewed | `LESS_THAN` | 100.0 % |

> **Minimum activation threshold** — coverage and duplication conditions are evaluated only when the
> change contains at least **20 added or modified lines**, so a two-line fix cannot fail the pipeline
> on a percentage computed from almost nothing.

---

## 4. Rule identifiers

```
QG-<LANG>-<CAT>-<NNNN>
```

* **`<LANG>`** — `ALL` (multi-language), `CS` (C# and VB.NET), `JV`, `JS`, `TS`, `PY`, `PP` (PHP),
  `GO`, `RB`, `KT`, `RS` (Rust), `CC` (C/C++), `SH`, `TF`, `DK`, `K8`, `CF`, `CSS`, `SQL`, `HTML`,
  `XML`, `RAZ` (Razor), `XAML`.
* **`<CAT>`** — `BUG` (correctness), `SEC` (security), `SML` (maintainability), `PRF` (performance),
  `CNV` (naming and formatting).
* **`<NNNN>`** — sequential per `(LANG, CAT)`, zero-padded, **never reused** — a number stays retired
  even when its rule is removed.

Severity and issue kind follow the category: `SEC` → vulnerability (major or above), `BUG` → bug,
`SML` / `CNV` / `PRF` → code smell.

---

## 5. Rules

**1038 rules are loaded and executable**, backed by **2560 catalog entries** (a catalog entry either
carries its own detection or documents a rule implemented in code).

| Area | Code | Rules |
| --- | --- | --- |
| C# / VB.NET | `CS` | 234 |
| Java | `JV` | 151 |
| Python | `PY` | 136 |
| JavaScript | `JS` | 96 |
| Kotlin | `KT` | 83 |
| Multi-language | `ALL` | 67 |
| PHP | `PP` | 58 |
| Rust | `RS` | 37 |
| Go | `GO` | 28 |
| Ruby | `RB` | 26 |
| C / C++ | `CC` | 16 |
| Terraform | `TF` | 16 |
| Docker | `DK` | 14 |
| Kubernetes | `K8` | 14 |
| Shell | `SH` | 13 |
| TypeScript-specific | `TS` | 10 |
| CSS | `CSS` | 10 |
| HTML | `HTML` | 9 |
| SQL | `SQL` | 9 |
| Razor / XAML / XML | `RAZ`, `XAML`, `XML` | 11 |

Every rule ships an English **summary**, a **why is this an issue** explanation and a **how to fix**
section; the CLI prints the fix guidance with `--fix-hints`, and SARIF carries it in the rule
metadata.

### Rules as data

A rule can be written declaratively in `src/QualityGuard.Core/Rules/Catalog/*.yaml`:

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

Matchers cover invocations (with receiver, arguments, argument literals), object creations, member
accesses, identifiers, string literals, assignments, declared and parameter types, and line patterns,
plus filters such as `argTainted`, `argDynamic`, `resultUnused`, `withoutArgs`, `requires`, `absent`.
Anything that needs real reasoning over the tree is written in C# instead, against `SyntaxQuery`, the
semantic model and the taint result.

### Security coverage

Command injection, SQL injection, path traversal, open redirect, server-side request forgery, unsafe
deserialization, XML external entities, dynamic code execution, weak cryptography (broken hashes,
obsolete ciphers, ECB, predictable randomness, weak key sizes), disabled certificate validation,
cleartext transport, hardcoded credentials, permissive CORS, insecure cookies, and infrastructure as
code (open CIDR blocks, unencrypted storage, wildcard IAM policies, privileged containers).

---

## 6. Scanning files and folders

`--path` accepts a **file** or a **directory**, and a directory is walked all the way down, including
every subfolder. The option is repeatable and accepts comma-separated values, so several trees can be
analysed in one run.

```bash
# one file
dotnet run --project src/QualityGuard.Cli -- --path ./src/App/Program.cs

# a tree, with a per-directory summary
dotnet run --project src/QualityGuard.Cli -- --path ./src --by-folder

# several trees, only C#, skipping generated code
dotnet run --project src/QualityGuard.Cli -- \
  --path ./src,./tests \
  --include "**/*.cs" \
  --exclude "**/Generated/**"
```

What is skipped by default, because analysing it produces findings nobody can act on:

* dependency and build directories — `bin`, `obj`, `build`, `dist`, `out`, `target`, `node_modules`,
  `bower_components`, `packages`, `vendor`, `venv`, `__pycache__`, `coverage`, `Pods`, `.git`, `.gradle`,
  `.terraform` and similar (the directory is never opened);
* generated and bundled files — `*.min.js`, `*.bundle.js`, `*.map`, `*-lock.json`, `*.designer.cs`,
  `*.generated.*`, `*.pb.go`, `*_pb2.py`, `*.d.ts`, `*.snap`;
* files larger than `--max-file-kb` (default 2048) and anything with a NUL byte in its first 512 bytes.

Pass `--all-files` to keep them. A path that does not exist is reported as a warning and does not stop
the scan; `--verbose` prints how many files were skipped and why.

---

## 7. CLI

```bash
# scan, custom gate, SARIF export
dotnet run --project src/QualityGuard.Cli -- \
  --path ./src --gate ./config/gate.json --sarif ./artifacts/report.sarif.json

# evaluate the gate from an existing SARIF report
dotnet run --project src/QualityGuard.Cli -- \
  --sarif-in ./artifacts/input.sarif.json --gate ./config/gate.json

# derive the new_* ratings from the findings
dotnet run --project src/QualityGuard.Cli -- --path ./src --new-code
```

| Option | Function |
| --- | --- |
| `--path <dir\|file>` | Scan a file or a directory tree. Repeatable, comma-separated values allowed. |
| `--include <glob>` | Only scan files matching the glob (`**` crosses directories, `*` stays inside one, `?` is one character). |
| `--exclude <glob>` | Skip files or directories matching the glob. |
| `--all-files` | Keep the build, dependency and generated files skipped by default. |
| `--max-file-kb <n>` | Skip files above this size (default 2048). |
| `--by-folder` | Print a per-directory summary of files, ncloc, bugs, vulnerabilities and code smells. |
| `--gate <json>` | Custom Quality Gate configuration; falls back to the built-in profile. |
| `--sarif <out.json>` | Export findings and gate state as SARIF 2.1.0. |
| `--sarif-in <file>` | Read metrics from an existing SARIF report instead of scanning. |
| `--new-code` | Map finding counts into the `new_*` rating metrics before evaluating the gate. |
| `--fix-hints` | Print the remediation steps under every finding. |
| `--verbose` | Per-file metrics, taint flow steps and what the scan skipped. |
| `--rules` | List loaded rules and description coverage. |
| `--dump-ast` | Print the syntax tree of one file. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | `PASSED` — every gate condition met. |
| `1` | `FAILED` — at least one condition failed. |
| `2` | `ERROR` — invalid arguments, missing input or a runtime failure. |

### Example output

```
QUALITY GATE: Passed
  [OK  ] new_coverage: N/A vs 80.0 (LessThan) - passed
  ISSUE QG-CS-SEC-0018 Critical: Validate the path to prevent path traversal. (src/DocumentService.cs:10)
      flow  line 7: 'ReadRequestedFile' returns data that enters the program in RequestReader.cs
      flow  line 10: tainted value reaches this sink

FOLDER                                     FILES   NCLOC  BUGS  VULN SMELLS
src/QualityGuard.Core/Analysis                10    1042     5     3     66
src/QualityGuard.Core/Semantics                3     416     1     0     21
```

---

## 8. Quality bar

The engine is measured on real code, not only on fixtures: every new rule is run against this
repository and against a real project in the rule's own language before it is considered finished. A
rule that produces noise is rewritten on the syntax tree or removed, and the false positives that were
fixed are pinned by regression tests so the precision cannot be lost again silently.

Automated checks:

```bash
dotnet build QualityGuard.sln
dotnet test                       # parser, semantics, taint, scanner, rule precision
./tools/RuleCatalog.ps1 -Validate # catalog shape, identifiers, English descriptions
```

---

## 9. Non-goals

* No database or SQL persistence — the engine is strictly in-memory.
* No UI or web dashboard — output is the console and SARIF.
* No server or background orchestration — it is an ephemeral CLI runner.
* No user management, RBAC or SSO.
* No mandatory coupling to a hosting platform or cloud service.
