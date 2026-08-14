# QualityGuard — Comprehensive Technical Architecture & Domain Specification

**QualityGuard** is a lightweight, **stateless, and in-memory** code quality engine built in **C#**. It is designed specifically for execution within continuous integration (CI) pipelines such as GitHub Actions, Azure DevOps, and GitLab CI.

It evaluates metrics against configurable Quality Gate conditions, executes static code analysis across multiple languages, and outputs deterministic results (**PASSED** or **FAILED**) with actionable explanations.

---

## 1. Core Architecture & NuGet Package Structure

QualityGuard is structured as a modular set of C# assemblies with zero external server or database dependencies:

| Project / Package | Role & Responsibility |
| --- | --- |
| **`QualityGuard.Core`** | Core domain models, tokenization engine, taint analysis, sliding-window duplication detector, rule framework, and in-memory gate evaluator.

 |
| **`QualityGuard.Sources.Sarif`** | Reader and writer for the standard **SARIF 2.1.0** format, extracting metrics and exporting structured analysis findings.

 |
| **`QualityGuard.Cli`** | Executable CLI entry point designed to run inside pipeline jobs, returning explicit exit codes (`0` for success, non-zero for failures).

 |

---

## 2. Domain Model & Evaluation Pipeline

### Key Domain Entities

* **`Metric` / `CoreMetrics**`: Key metrics tracked during analysis, centered on new code modifications:


* `new_coverage`: Test coverage percentage on new code.


* `new_duplicated_lines_density`: Percentage of duplicated lines on new code.


* `new_security_rating`: Security rating on new code ($1 \dots 5$, where $1 = \text{A}$).


* `new_reliability_rating`: Reliability rating (bugs) on new code ($1 \dots 5$).


* `new_maintainability_rating`: Maintainability rating (code smells) on new code ($1 \dots 5$).


* `new_security_hotspots_reviewed`: Percentage of reviewed security hotspots on new code.




* **`Condition`**: A Quality Gate rule containing a `metricKey`, an `operator` (`LESS_THAN`, `GREATER_THAN`), and a numeric `threshold`.


* **`QualityGateResult`**: Overall analysis output containing global status (`PASSED` or `FAILED`) and per-condition evaluation results.


* **`Severity`**: Issue severity levels: `BLOCKER`, `CRITICAL`, `MAJOR`, `MINOR`, and `INFO`.


* **`Issue Types`**: Categorized into `Bug`, `Vulnerability`, and `Code Smell`.


* **`Technical Debt`**: Estimated remediation effort associated with identified findings.



### 3-Stage Evaluation Pipeline

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────────────┐
│  MetricReader   │ ---> │    Evaluator     │ ---> │    StatusCalculator     │
│ (Reads Metrics) │      │(Evaluates Rules) │      │ (Outputs PASSED/FAILED) │
└─────────────────┘      └──────────────────┘      └─────────────────────────┘

```

1. **`MetricReader`**: Receives a `Map<string, double>` of measured metric values for the commit/PR.


2. **`Evaluator`**: Iterates over active conditions and compares measured values against configured thresholds.


3. **`StatusCalculator`**: If **at least one** condition fails, the global gate status resolves to `FAILED`.



---

## 3. Standard Quality Gate Profile & Fudge Factor

QualityGuard provides a pre-configured standard gate profile targeting new code:

| Metric | Operator | Error Threshold |
| --- | --- | --- |
| **New Coverage** | `LESS_THAN` | **80.0%**<br> |
| **New Duplicated Lines** | `GREATER_THAN` | **3.0%**<br> |
| **New Maintainability Rating** | `GREATER_THAN` | **1** (Worse than A)

 |
| **New Security Hotspots Reviewed** | `LESS_THAN` | **100.0%**<br> |
| **New Reliability Rating** | `GREATER_THAN` | **1** (Worse than A)

 |

> **Fudge Factor (Minimum Threshold)**: To prevent false-positive pipeline failures on tiny modifications, conditions on *Coverage* and *Duplication* are evaluated **only if** the pull request or commit contains at least **20 modified or added lines of code**.
> 
> 

---

## 4. Proprietary Rule ID Schema (`QG-*`)

QualityGuard implements a strictly structured, proprietary rule identification schema:

$$\text{Rule ID Format: } \mathbf{QG-\langle LANG \rangle-\langle CAT \rangle-\langle NNNN \rangle}$$

* **`<LANG>` (Language Scope)**:
* `ALL` (Multi-language)


* `CS` (C# / VB.NET), `JV` (Java), `JS` (JavaScript), `TS` (TypeScript), `PY` (Python), `PP` (PHP), `GO` (Go), `RB` (Ruby), `KT` (Kotlin), `CC` (C/C++), `SH` (Shell)


* `TF` (Terraform), `DK` (Docker), `K8` (Kubernetes), `CF` (CloudFormation), `AR` (ARM)


* `CSS` (CSS), `SQL` (SQL), `HTML` (HTML), `XML` (XML)




* **`<CAT>` (Category)**:
* `BUG` (Correctness / Bugs)


* `SEC` (Security / Vulnerabilities)


* `SML` (Code Smells / Maintainability)


* `PRF` (Performance)


* `CNV` (Naming / Formatting Conventions)




* **`<NNNN>`**: Sequential 4-digit zero-padded number per (`LANG`, `CAT`) starting at `0001`.



---

## 5. Complete Language Support & Rule Catalog Breakdown

QualityGuard features **263 total built-in rules** (258 language-specific rules + 5 generic multi-language rules):

| Language / Area | LANG Code | Implementation File | Security Rules (SEC) | Quality Rules (SML/CNV/BUG/PRF) | Total Rules |
| --- | --- | --- | --- | --- | --- |
| **C# / VB.NET** | `CS` | `CSharpRules.cs` | 11 | 9 | **20**<br> |
| **Java** | `JV` | `JavaRules.cs` | 12 | 10 | **22**<br> |
| **Kotlin** | `KT` | `KotlinRules.cs` | 12 | 10 | **22**<br> |
| **JavaScript / TypeScript** | `JS` / `TS` | `JsTsRules.cs` | 17 | 9 | **26**<br> |
| **Python** | `PY` | `PythonRules.cs` | 14 | 6 | **20**<br> |
| **Ruby** | `RB` | `RubyRules.cs` | 9 | 4 | **13**<br> |
| **Go** | `GO` | `GoRules.cs` | 8 | 5 | **13**<br> |
| **PHP** | `PP` | `PhpRules.cs` | 15 | 7 | **22**<br> |
| **Terraform** | `TF` | `TerraformRules.cs` | 14 | 2 | **16**<br> |
| **Docker** | `DK` | `DockerRules.cs` | 8 | 6 | **14**<br> |
| **Kubernetes** | `K8` | `KubernetesRules.cs` | 9 | 5 | **14**<br> |
| **C / C++** | `CC` | `CCRules.cs` | 10 | 6 | **16**<br> |
| **Shell Scripting** | `SH` | `ShellRules.cs` | 7 | 6 | **13**<br> |
| **CSS** | `CSS` | `CssRules.cs` | 0 | 7 | **7**<br> |
| **SQL** | `SQL` | `SqlRules.cs` | 5 | 4 | **9**<br> |
| **HTML** | `HTML` | `MarkupRules.cs` | 5 | 2 | **7**<br> |
| **XML** | `XML` | `MarkupRules.cs` | 3 | 1 | **4**<br> |
| **Generic Multi-Language** | `ALL` | `BuiltInRuleRegistrar.cs` | 0 | 5 | **5**<br> |
| **TOTAL** |  |  | **164** | **99** | **263**<br> |

---

## 6. Security Analysis & Advanced Engine Capabilities

### Security Vulnerability Coverage

QualityGuard inspects code across major security flaw categories using heuristic token and line analysis:

* **OS Command Injection**: Detects unsafe system calls (e.g., `Process.Start` in C#, `Runtime.exec` in Java, `child_process` in JS, `subprocess` in Python, `system`/`exec` in PHP/Ruby/Shell).


* **SQL Injection**: Identifies dynamic string concatenations (`+`, `$"..."`, `%`, f-strings) inside database execution methods.


* **Weak Cryptography**: Flags weak algorithms (`MD5`, `SHA-1`, `DES`, `3DES`, `RC4`, `ECB` mode).


* **Hardcoded Credentials**: Detects secrets, tokens, API keys, and passwords assigned to string literals.


* **Arbitrary Code Execution**: Flags unsafe execution sinks like `eval()`, `exec()`, and dynamic function invocation.


* **Insecure Deserialization**: Identifies unsafe serialization parsers (e.g., `BinaryFormatter`, `pickle.loads`, `ObjectInputStream`, `unserialize`).


* **Infrastructure as Code (IaC)**: Checks for open CIDR blocks (`0.0.0.0/0`), unencrypted databases, wildcard IAM policies, `root` container execution, and insecure Kubernetes privileges (`privileged: true`, `hostNetwork`).



### Dataflow-Lite Taint Analysis (`TaintAnalyzer`)

`QualityGuard.Core` incorporates a line/token-level taint analysis engine:

* **Sources**: Tracks untrusted input points (e.g., `Request.QueryString`, `os.environ`, `$_GET`/`$_POST`, `sys.argv`, `getenv`).


* **Propagation**: Propagates taint status through variable assignments (`x = source`) across file lines.


* **Sinks**: Exposes `IsTainted(variable)` and `IsTaintedLine(line)` methods to rule checks to validate whether tainted data reaches sensitive sinks.



### Code Duplication Detection (`DuplicationDetector`)

* Utilizes **lexical tokenization** (`SourceTokenizer`) supporting 19 built-in grammar profiles.


* Applies a **sliding-window hashing algorithm** to identify duplicate code blocks across files without requiring full AST compilation.



---

## 7. CLI Execution & Pipeline Workflow

The `QualityGuard.Cli` tool serves as the interface for CI/CD environments:

```bash
# Direct source scanning with custom gate rules and SARIF output export
dotnet run --project src/QualityGuard.Cli -- \
  --path ./src \
  --gate ./config/gate.json \
  --sarif ./artifacts/report.sarif.json

# Evaluates Quality Gate against an existing SARIF file
dotnet run --project src/QualityGuard.Cli -- \
  --sarif-in ./artifacts/input.sarif.json \
  --gate ./config/gate.json

# Derives ratings (new_*) directly from issue findings
dotnet run --project src/QualityGuard.Cli -- \
  --path ./src \
  --new-code

```

### Command Line Options

| Option | Function |
| --- | --- |
| `--path <dir|file>` | Scans directory/file (tokenization + metrics + duplication + rules + gate).

 |
| `--sarif-in <file>` | Reads metrics directly from an existing SARIF 2.1.0 report.

 |
| `--gate <json>` | Path to custom Quality Gate JSON config (falls back to built-in gate).

 |
| `--sarif <out.json>` | Exports analysis findings and gate execution state to SARIF.

 |
| `--new-code` | Opt-in flag to map finding counts into `new_*` metric ratings.

 |

### Pipeline Exit Codes

* **`0`**: `PASSED` — All Quality Gate conditions met.


* **`1`**: `FAILED` — One or more Quality Gate conditions failed.


* **`2`**: `ERROR` — Execution error (invalid arguments, missing files, runtime exception).



---

## 8. Explicit Non-Goals & Scope Boundaries

To maintain high performance and simplicity inside CI jobs, QualityGuard explicitly excludes:

* ❌ **No Database / SQL Persistence**: Operates strictly in-memory.


* ❌ **No UI / Web Dashboard**: Outputs directly to standard logs and SARIF files.


* ❌ **No Server / Background Orchestration**: Designed as an ephemeral CLI runner.


* ❌ **No User Management / RBAC / SAML**: No authentication or user access management.


* ❌ **No Third-Party Platform Coupling**: Independent execution without mandatory cloud dependencies.
