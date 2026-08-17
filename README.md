# QualityGuard

**QualityGuard** is a stateless, in-memory code quality engine written in C# for continuous
integration pipelines. It parses source code, computes metrics, runs static analysis rules, evaluates
a configurable Quality Gate and exits with `PASSED` or `FAILED` — no server, no database, no UI.

```bash
dotnet run --project src/QualityGuard.Cli -- --path ./src --by-folder
```

**1314 rules** across 26 languages, on a real syntax tree with a semantic model, a project index and
interprocedural taint analysis. The bar the engine is held to is precision: every rule is measured on
a production codebase in its own language before it is kept, and a rule that produces noise is
rewritten or removed — see [§8](#8-quality-bar).

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

* **Syntax tree** — recursive-descent parsers for C#, Java, Go, JavaScript, TypeScript, PHP and Dart
  (one C-family parser with a dialect each) and an indentation-driven parser for Python. Everything
  else — Kotlin, Swift, Ruby, Rust, C/C++, VB.NET, shell, SQL — falls back to a generic structural
  parser that still recognises declarations, blocks and control flow;
  `SyntaxTree.HasDedicatedParser` tells a rule whether the tree is exact enough to reason about
  statements, and a rule that needs more stays silent rather than guessing.
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

### Quality numbers

Every figure in the report is derived from the findings, so it can be traced back to the lines that
produced it. The CLI prints them after each run:

| Number | How it is computed |
| --- | --- |
| Bugs / vulnerabilities / hotspots / code smells | counted by kind, broken down by severity |
| **Reliability rating** | from the **worst** bug: A = none, B = minor, C = major, D = critical, E = blocker |
| **Security rating** | same scale, over the vulnerabilities |
| **Technical debt** | sum of the remediation effort of the code smells (`5min`, `1h30min`, `2d`; a day is 8 hours). A rule that never stated a duration contributes a fixed amount for its severity, so the total never depends on which words a rule happened to use |
| **Debt ratio** | debt divided by the estimated cost of writing the code (30 minutes per line) |
| **Maintainability rating** | from the ratio: A ≤ 5 %, B ≤ 10 %, C ≤ 20 %, D ≤ 50 %, E above |
| **Duplicated lines density** | duplicated lines over total ncloc |

A rating follows the worst finding rather than the number of findings: one blocker has to outweigh
forty minor smells, otherwise the letter says nothing and nobody acts on it. Maintainability is the
exception, because "twelve smells" means something different in a hundred lines and in a hundred
thousand.

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

* **`<LANG>`** — `ALL` (multi-language), `SEC` (secrets, every language), `CS` (C# and VB.NET),
  `JV`, `JS`, `TS`, `PY`, `PP` (PHP), `GO`, `RB`, `KT`, `SW` (Swift), `RS` (Rust),
  `DART` (Dart and Flutter),
  `CC` (C/C++), `SH`, `TF`, `DK`, `K8`, `CF`, `CSS` (CSS, SCSS, Sass, Less), `SQL`, `HTML`, `JSON`,
  `XML`, `RAZ` (Razor), `XAML`.
* **`<CAT>`** — `BUG` (correctness), `SEC` (security), `SML` (maintainability), `PRF` (performance),
  `CNV` (naming and formatting).
* **`<NNNN>`** — sequential per `(LANG, CAT)`, zero-padded, **never reused** — a number stays retired
  even when its rule is removed.

Severity and issue kind follow the category: `SEC` → vulnerability (major or above), `BUG` → bug,
`SML` / `CNV` / `PRF` → code smell.

---

## 5. Rules

**1312 rules are loaded and executable**, backed by **2626 catalog entries** (a catalog entry either
carries its own detection or documents a rule implemented in code).

Coverage is tracked honestly in `rules-tracker.tsv`: **3256 catalogued rules are mapped, 1515 of them
executable**. The rest are documented and deliberately silent — a rule counts as implemented only
when it detects something and has been measured on real code.

| Area | Code | Rules |
| --- | --- | --- |
| C# / VB.NET | `CS` | 253 |
| Java | `JV` | 198 |
| Python | `PY` | 173 |
| JavaScript | `JS` | 140 |
| Kotlin | `KT` | 83 |
| Swift | `SW` | 14 |
| Multi-language | `ALL` | 94 |
| Dockerfile | `DK` | 21 |
| CSS / SCSS / Sass / Less | `CSS` | 19 |
| HTML | `HTML` | 41 |
| Dart / Flutter | `DART` | 7 |
| Secrets (every language) | `SEC` | 5 |
| JSON | `JSON` | 3 |
| PHP | `PP` | 76 |
| Rust | `RS` | 37 |
| Go | `GO` | 28 |
| Ruby | `RB` | 26 |
| C / C++ | `CC` | 16 |
| Terraform | `TF` | 21 |
| Kubernetes | `K8` | 14 |
| Shell | `SH` | 13 |
| TypeScript-specific | `TS` | 10 |
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

### Java and Python on the tree

Both have a real parser here, so their rules read declarations, catches, switches and calls instead
of lines — which is what lets them stay quiet on the shapes that only resemble the defect.

* **Java** — the contracts the platform expects a type to honour: an iterator whose `next` never
  throws `NoSuchElementException`, a `wait` outside its loop (a thread can wake with nothing having
  changed), a `Boolean` method returning `null` (which every `if` unboxes into a null pointer), a
  thread started from a constructor, `iterator()` returning `this`, a JDBC accessor given index 0, a
  date pattern written with upper-case `Y` (the week year — wrong for the last days of December),
  `compareTo` overloaded. Then the declarations that say one thing and do another: a class of static
  members that can still be constructed, a field set to the value it already has, an interface member
  repeating `public`, double brace initialization, an override of `clone`, an instance method writing
  to a static field, an empty statement. Plus an override of `finalize`, a class extending `Error`, a jump label sitting among the
  cases of a switch, a method one letter away from `toString` or `equals`, a method named after its
  own class, a mutable `public static` field, a `hasNext` that advances the iterator, a `BigDecimal`
  built from a `double`, a catch that drops the cause or sorts exceptions with `instanceof`, an
  import from an internal JDK package, `main` declaring `throws`, and the small readability ones
  (`String.valueOf` inside a concatenation, `toString` on a string, a negated comparison, a lambda
  wrapping one expression in a block).
* **Python** — the code that imports cleanly and fails the first time it runs: a mutable default
  argument (created once and shared by every call that omits it), a raised literal, a keyword
  argument given twice, `__exit__` re-raising what it was handed, an `except` clause a wider one
  already covers, a constant used as a condition, an invalid `open` mode, an unhashable dictionary
  key, a comparison against `nan` (equal to nothing, itself included), a value returned from a
  generator (which every `for` loop discards), an exception class with no base. Plus `break` outside
  a loop, `__init__` returning a value, a non-name in `__all__`, a loop
  `else` with no `break`, a repeated key in a dictionary or element in a set, an `assert` given a
  tuple (which can never fail), an exact type comparison instead of `isinstance`, a slice compared
  against a literal instead of `startswith`, a lambda bound to a name, nested conditional
  expressions, a lone handler that only re-raises, and the receiver conventions for instance and
  class methods.

These were measured on real code before being kept: a full Java analyzer codebase (2700 files,
249k ncloc) and the CPython standard library (542 files, 213k ncloc). They are quiet on clean code
and loud on defective code — the duplicated dictionary keys they report in the standard library are
real, and so are the `for`/`else` blocks with no `break`.

### PHP on the tree

PHP is parsed as a dialect of the C-family parser, so these rules read declarations, catches and
calls: a variable whose name is computed, a PHP 4 constructor (an ordinary method since PHP 8, so
the object is now built without it), `$this` in a static method, a catch clause an earlier one
already covers, the same variable passed twice to one call, a thrown literal, a `foreach` reference
that is never `unset` — the surprise where the last element of the array silently becomes a copy of
the one before it — a constant defined twice, an error hidden by the `@` operator, and the
declaration habits (`var`, several properties per statement, a method with no visibility, a default
argument that can never be used, `exit` inside a function, an alias such as `sizeof`).

### C# and JavaScript on the tree

* **C#** — the shape of a type and the contract it offers: a public field, a class of static members
  that can still be constructed, a general exception thrown, an `[Obsolete]` with no message, a
  property that only wraps a field or that can only be written, an empty constructor or finalizer, a
  type outside any namespace, a method that always returns the same literal. Plus the expressions
  that compile cleanly and mean something else: `x % 2 == 1` (false for every negative number),
  `IndexOf(...) > 0` (which excludes the first element), `new Guid()` (always the empty one), a
  getter that throws, a `protected` member in a sealed class, and `ToString`, `Equals`, `GetHashCode`
  or `Dispose` throwing — all four are called by the runtime, and `Dispose` throwing during
  unwinding replaces the original failure.
* **JavaScript and TypeScript** — what the code does with the values it has: a string method whose
  result is thrown away (strings do not change), a `typeof` compared to a word it never returns, a
  `for-in` over an array, a hole left by a double comma, a self-assignment, a name declared twice in
  one block, a union that lists the same type twice, `new Function`, `name: name`, the `arguments`
  object, a nested template literal, `any`, two imports of one module, a setter with no getter. Plus
  a jump label among the cases of a switch, `&` where `&&` was
  meant, an assignment to `undefined` or `arguments`, a built-in prototype extended, a setter that
  returns a value, `indexOf(...) > 0`, `sort()` with no comparator (which compares numbers as text),
  a generator that never yields, a thrown string, `${...}` inside a quoted string, an empty
  destructuring pattern, `!a in b`, `new Symbol()`, `=== true`, `new Object()`, and `this` copied
  into a variable.

Measured on real code before being kept: the reference C# analyzer suite (1405 files, 92k ncloc) and
a TypeScript codebase of 2588 files and 200k ncloc, plus this repository. On that TypeScript corpus
the sixteen JavaScript rules together produce fifteen findings.

### Web front ends

Stylesheets and markup are parsed, not matched line by line, because their defects are relationships:

* **CSS, SCSS, Sass, Less** — a property set twice in one block, a shorthand that cancels the longhand
  above it, an empty block, systematic `!important`, a duplicated selector, a font stack without a
  generic family, an `@import` after the first rule (which the browser silently ignores), nesting too
  deep to follow, a `z-index` outside any scale.
* **HTML** — the page as a whole (a missing doctype, a missing title, a viewport that forbids
  zooming, skipped heading levels), the element that only works when a second one is present (a
  fieldset and its legend, a video and its captions, a list item and its list, an object and its
  fallback), the relationship that carries the meaning (an image and its alternative text, a control
  and the label that names it, a `srcset` candidate and its descriptor, a table and its header
  cells), and the attribute that quietly takes something away from the user (`aria-hidden` on
  something focusable, a positive `tabindex`, an `accesskey`, a mouse handler with no keyboard
  equivalent, a link that leads nowhere). On the security side: a remote script with no integrity
  hash, a URL that carries code, `target="_blank"` without `rel="noopener"`, behaviour written into
  the markup. Template syntax (`{{ }}`, `${ }`, `<% %>`) is treated as dynamic and never judged, and
  an element driven by a component library — a `data-` hook, a directive, an explicit `role` — is
  read as a control, not as a mistake.
* **JSON** — duplicated keys, credentials committed in configuration, dependencies left open to any
  future version.

### Mobile: Dart and Flutter

Dart is parsed with the C-family parser, so it gets the full syntax tree and every shared structural
rule, plus the mistakes that belong to the framework: `setState` called during `build`, a mutable
field on a `StatelessWidget`, a controller or subscription never released in `dispose`, an `async`
function that never awaits, and a `BuildContext` used after an `await` without checking `mounted` —
the crash that only reaches users who tap quickly.

### Mobile: Swift

Swift is tokenized and read with the structural parser, which is enough for the defects that matter
on a phone: the operators the compiler lets through on purpose (`try!`, `as!`), the call that
deadlocks the main queue, an error caught and dropped, a secret written to `UserDefaults` instead of
the keychain, a query built by interpolation, plain HTTP, a broken hash. There is no reference
catalog behind these — they are written from the language — and no Swift corpus on the build machine,
so each one is pinned by a test that also states the shape it must stay silent on.

### Mobile: Kotlin

Kotlin is read with the structural parser and carries 83 rules — coroutines and dispatchers, Android
intents and broadcast receivers, WebView settings, the not-null assertion operator, `SharedPreferences`
holding a secret. The work that mattered here was precision rather than count: an extension function,
a `@Composable`, a trailing lambda and the word "token" in a parser were all being reported, and
Jetpack Compose alone accounted for hundreds of findings. See [§8](#precision-on-kotlin).

A Kotlin dialect for the C-family parser is the next step: it would unlock the ~90 shared structural
rules that stay silent today because the tree is not exact enough. It belongs on the TypeScript
branch, not the Java one — `fun f(a: Int): String` puts the type after the name, as TypeScript does.

### Secrets, in every language

Credentials are found by shape, not by context: AWS, Google and Azure keys, Stripe keys, GitHub,
GitLab and npm tokens, private key blocks, connection strings carrying their password, Slack, Discord
and Telegram webhooks. Each pattern is anchored on the provider's own prefix, and test fixtures,
examples and documentation are skipped, so the rule stays believable.

### Infrastructure as code

Configuration files are read as a **tree of keys and blocks**, not as lines, so a rule can see the
relationship that makes a finding true: a port opened next to its source range, a flag inside a
container's security context, a setting missing from the resource that needs it. Two syntaxes are
covered by one reader — braces with labels (Terraform, JSON) and indentation with list items
(Kubernetes, CloudFormation) — and Dockerfiles are read as their instruction list.

* **Terraform** — storage without encryption at rest, resources reachable from the whole internet,
  outdated TLS versions, logging switched off, policies granting every action to everyone.
* **Kubernetes** — privileged containers, privilege escalation, host namespaces, running as root,
  missing resource limits, writable root filesystem, unpinned images, wildcard RBAC.
* **Dockerfile** — lower-case instructions, relative WORKDIR, duplicated CMD/ENTRYPOINT, ADD for
  local files, the whole build context copied into the image, spaces around `=` in ENV/ARG, runs of
  consecutive RUN instructions, unpinned base images, secrets in ENV.

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

The engine is measured on real code, not only on fixtures: every new rule is run against this
repository and against a real project in the rule's own language before it is considered finished. A
rule that produces noise is rewritten on the syntax tree or removed, and every false positive that
was fixed is pinned by a regression test — written next to the shape the rule must still report — so
the precision cannot be lost again silently.

**505 tests** cover the parsers, the semantic model, taint, the scanner and rule precision.

```bash
dotnet build QualityGuard.sln
dotnet test                       # parser, semantics, taint, scanner, rule precision
./tools/RuleCatalog.ps1 -Validate # catalog shape, identifiers, English descriptions
```

### Measured against the reference engine's own expectations

Analyzer projects ship test corpora whose defective lines are annotated — a comment on each line that
must be reported. That is a ground truth written by someone else, for a different engine, without
any knowledge of this one, which makes it a usable instrument:

```bash
python tools/compare_expectations.py --path <corpus> --language py
```

It reports **recall** (how many expected lines QualityGuard finds), **precision** (how many of its
findings land on an expected line), and the findings on unannotated lines — meant to be read rather
than counted, since the two catalogues do not coincide and a file written to exercise one check
usually contains other defects nobody annotated.

| Corpus | Annotated files | Expected lines | Recall | Precision |
| --- | --- | --- | --- | --- |
| C# | 1,079 | 11,238 | **65.8%** | 38.3% |
| Go | 52 | 234 | **69.2%** | 47.7% |
| JavaScript | 109 | 921 | **53.2%** | **50.8%** |
| Python | 611 | 6,451 | **51.4%** | 40.6% |
| Kotlin | 159 | 2,030 | **53.3%** | 49.8% |
| Java | 1,004 | 10,130 | **46.0%** | 36.7% |
| PHP | 285 | 2,482 | **44.3%** | 47.3% |
| VB.NET | 254 | 2,392 | **40.4%** | **64.5%** |

Recall sits above the share of rules ported in every language measured. It is the number each new
wave has to move, and the honest answer to "how much is still missing".

The tool also names the checks it covers least (`--missing`), and the waves are chosen from the top
of that list rather than from taste. The JavaScript wave took recall from 31.8% to 53.2% and
precision from 43.7% to 50.8% in the same pass; the PHP wave took recall from 38.9% to 44.3%.

**Recall borrowed from a noisy rule is not recall.** The Java figure fell once, in the pass that
fixed three structural rules, and that is the trade being made on purpose: those rules were landing
on marked lines by accident, because they reported on nearly everything. The same pass removed about
3,900 findings and lost 560 matched lines — seven out of eight of the findings that went away were on
lines nobody had marked. The engine now says less and is right more often, which is the only
direction that matters when the report is read by a person.

### Kotlin got a parser

Kotlin was read by the generic structural parser until this pass: the tree placed declarations but
did not resolve them, so `SyntaxTree.HasDedicatedParser` was false and the ninety-odd structural
rules skipped every Kotlin file. It now has a dialect of the C-family parser, built on the same
recursive descent as Java and TypeScript and differing where the language does:

- **A declaration names itself first.** `fun greet(name: String): String` puts the name before the
  type, which is the opposite of the shared member path, so functions, properties and parameters are
  parsed on their own.
- **A statement ends at the line break.** The terminators the language leaves out are rebuilt before
  parsing, the way the JavaScript dialect already did, with the continuations Kotlin adds — the elvis
  operator, the safe call, `is`, `in`, `by`.
- **`when` is a branch, not a call.** It is recorded as a match in both positions, statement and
  expression, so the rules about unhandled values and about complexity see it for what it is.
- **A trailing lambda is an argument.** `items.filter { it > 0 }` is how most of the language is
  written; read as a block it detached the body from the call and left every rule about that call
  blind.
- **A property of a type is a field.** Kotlin declares them with the same `val` a local uses, and
  reading them as locals reported every property as an unused variable.

Recall went from 47.0% to 53.3%. Precision fell from 56.5% to 49.8%, and that number needs reading
with care: the corpus annotates only the check each file was written to exercise, and the dialect
switched on fifty rules that now fire legitimately elsewhere in those same files. Every family in the
list of unannotated findings was read by hand — unused locals, `println` left in code, parameters
nobody uses, a `var` that is never reassigned — and each one is a defect the file really contains.

What the dialect did expose was three genuine faults, now fixed: `!!` was reported as a repeated
negation when it is a single operator, a `when` without an `else` was reported twice by two different
rules, and duplicated literals were reported by both the Kotlin rule and the shared one.

### A whole language was never measured

C# is the largest catalogue in the engine and the figure above is its first: until this pass, running
the analyzer over that corpus ended with `ERROR: Index was out of range` and no report at all. One
file — a deliberately malformed source, of the kind any repository being edited contains — sent the
attribute parser past the end of its token list, and the whole scan died with it.

Two things changed. The parser now checks that an attribute list actually closes before reading one,
instead of consuming the rest of the file looking for a bracket. And the engine no longer lets one
file end a run: a source it cannot read is recorded with its reason and the scan carries on, because
a quality gate that stops at the first surprise is worse than one that reports what it managed to
read. The corpus that produced nothing now produces 33,273 findings, 65.8% of the expected lines.

### One defect, one finding### One defect, one finding

A reader who is told the same thing three times stops reading. `tools/overlapping_rules.py` runs the
engine over a corpus and reports the rule pairs whose findings land on the same line:

```bash
python tools/overlapping_rules.py --path <corpus> --extension .java
```

On the Java corpus it found twenty such pairs, and on the C# one forty-five, and the largest was four rules for one defect: a call
to `System.out` was reported by a shared analyzer and by three separate ported entries, 1,076 times
each. Seven rules were retired in favour of the one that says it best. Retirement is recorded in the
catalogue rather than hidden: the entry keeps its documentation and takes `status: superseded` with
`superseded_by`, so the identifier keeps its meaning and is never handed to a different check. The
validator enforces that pairing.

Fifteen rules have been retired this way so far. Three of them said the same thing about
`System.out`, three about a thrown `Exception`, two about an empty method body. One was a security
rule that matched any call named `forName`, so `Charset.forName("UTF-8")` was reported as a
vulnerability; another was about the case of a numeric suffix and ran with case ignored, so it
reported `0L` and `54U` — the correct form — as mistakes.

Two of the retired rules were worse than redundant. *Unsafe APIs should not be used* and *Invalid
Date values should not be used* were both written as one-line matches — `new Random()` and
`new Date()` — which is not what either title claims. The first is gone; the second was rewritten to
do what it says, and now reports `new Date(2020, 13, 5)` and leaves `new Date(2020, 11, 5)` alone.

### Saying less on purpose

Four changes in this pass exist to make the report describe code someone actually wrote:

- **Generated files are not reviewed code.** A file whose first lines say a tool wrote it is skipped
  unless `--all-files` is given. On one production repository that removed 13 files — and with them
  half the counted lines, the 16.6% duplication figure, and 300 findings nobody could have acted on,
  since the next run of the generator would erase the fix.
- **Only a private method is asked to become static.** Anything else — an override, an interface
  implementation, a member a subclass replaces — is somebody's contract, and the engine cannot see
  those callers from one file.
- **An empty body that explains itself is left alone.** The rule asks for the emptiness to be
  documented, so a comment inside the body is the answer to it.
- **A security rule needs its receiver.** *Classes should not be loaded from names computed at run
  time* matched any call named `forName`, so every `Charset.forName("UTF-8")` was reported as a
  vulnerability. It now asks for `Class`.
- **A file is not binary because of one odd byte.** The scanner rejected any file with a zero byte in
  its first block, which silently dropped whole sources — including the ones holding exactly the
  control characters a rule exists to find. It now measures how much of the head is unreadable.
- **A repeated type name is only confusing among neighbours.** `Settings` exists once per module by
  design; the comparison is made within one folder instead of across the whole tree.

### What the measurements found

Four languages were audited by running the engine over production codebases and reading every
finding it produced. The pattern was the same each time: the noise did not come from rules that were
wrong in principle, but from rules that judged a name without knowing what it stood for, or a shape
without knowing what surrounded it. Nothing below removed a rule from the catalogue.

### Precision on VB.NET

A real VB codebase surfaced the worst defect found so far, and it was in the language definition
rather than in a rule: VB declared **two** string delimiters, `"` and `""`. The second does not exist
in the language — it was an attempt to model the doubled-quote escape — and since delimiters are
tried longest-first, every **empty string literal** opened a string that ran to the next `""` in the
file. The code in between was never analysed at all.

The block structure was wrong in five more ways, all because the end-keyword parser was written for
Ruby, where `end` stands alone: `End If` and `End Function` left their second word to start a new
construct, `Next`/`Loop`/`Wend` were not recognised as closers, a second `Catch` opened a block
inside the first, a one-line `If x Then y` opened a block nothing closed, and `With`/`Using`/
`SyncLock`/`Property`/`Namespace` opened no block at all, so their `End …` closed the enclosing
function's.

Each file collapsed into a single nesting chain: a twelve-line function with one `If` scored 75 on
cognitive complexity. On the codebase that found it, code smells went 1,789 → 601 and reported
complexity 3,925 → 1,717.

### Precision on Kotlin

Kotlin exercised the engine on a language read by the generic structural parser, and the answer was a
report nobody would open: on 16k lines of production Kotlin, 103 bugs, 70 vulnerabilities and 638
smells. Adding rules to that would have made it worse, so the noise came out first.

Two of the fixes were in the shared statement classifier and help every brace language: a declaration
keyword is now recognised behind its modifiers (`private const val x` used to parse as a nameless
expression), and it is only looked for in the header of a statement — `Foo::class.java` used to be
read as a class named `java`.

The rest were shapes Kotlin uses constantly: an extension function (`fun Context.report()`, whose
name is what follows the dot, not the receiver type), a `@Composable` function (upper camel case by
Android's own convention), a trailing lambda after `return`, and the word "token" in a parser, which
is a piece of syntax and not a credential. That last one was reported as a **vulnerability**.

### Precision on Go

Go has a dedicated parser and still reported 42 bugs in 3,179 lines of well-written production code.
Three rules, three different mistakes: `panic` flagged everywhere (it is how `main` and a code
generator stop, and a defect only in a function that already promises to return an `error`); `0755`
read as an accidental octal, when a permission mask is written in octal on purpose; and `defer`
inside a loop, expressed as a line pattern that only asked whether the file contained a loop
*somewhere*, so every `defer` in a file with a `for` was reported.

That last one is now a rule on the tree, and it marks a limit of the declarative catalogue:
**containment is a question the matcher cannot express**. A rule that depends on "inside X" is
written in C#.

### Precision on Java and C#

The two languages with the most rules, and one parser gap behind several findings: the body of an
**anonymous class** (`new X() { ... }`) was read as an object initializer, so every method it
overrode became a call — and `public void addUnique(String t) { }` was reported as a void call used
as a value.

Four shared rules were then narrowed to shapes these languages use every day: an expression lambda
over a void call (which is how every `Consumer` is written), a local initialised from a method of the
same name (`boolean isSubscribed = isSubscribed(tree)`), a parameter of an abstract method or an
empty hook (there is no body to use it in), and a constructor forwarding with `: this(...) { }`.

Two C# rules were rewritten because they could not be defended. **Commented-out code** needed only a
semicolon anywhere in a comment, so it reported every licence header — the first comment of every
file. **Null dereference** marked a name for the whole file and then flagged every later member
access, without flow, without scope, and without noticing the `??=` three lines above; it is now
limited to the one honest form available without flow analysis — a value that comes back from an
`...OrDefault()` and is dereferenced in the very next statement.

### The numbers

| Corpus | Bugs | Vulnerabilities | Code smells |
| --- | --- | --- | --- |
| Kotlin, 16k ncloc | 103 → **60** | 70 → **24** | 638 → **447** |
| Go, 3.2k ncloc | 42 → **12** | 4 | 84 |
| Java, 32k ncloc | 105 → **66** | 11 | 614 → **442** |
| C#, 92k ncloc | 368 → **282** | 52 | 5626 → **3127** |
| This repository, 79k ncloc | 88 → **42** | 56 | 1436 → **1301** |

---

## 9. Non-goals

* No database or SQL persistence — the engine is strictly in-memory.
* No UI or web dashboard — output is the console and SARIF.
* No server or background orchestration — it is an ephemeral CLI runner.
* No user management, RBAC or SSO.
* No mandatory coupling to a hosting platform or cloud service.
