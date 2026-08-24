# QualityGuard

**QualityGuard** is a stateless, in-memory code quality engine written in C# for continuous
integration pipelines. It parses source code, computes metrics, runs static analysis rules, evaluates
a configurable Quality Gate and exits with `PASSED` or `FAILED` — no server, no database, no UI.

```bash
dotnet run --project src/QualityGuard.Cli -- --path ./src --by-folder
```

**3980 rules across 27 languages**, of which **639 are security rules**, on a real syntax tree with a
semantic model, a project index and interprocedural taint analysis. The coverage goes past the
languages themselves: AWS, Azure and Google Cloud infrastructure (Terraform, CloudFormation),
Kubernetes manifests, Dockerfiles, Android manifests and Gradle build scripts, Java EE and ASP.NET
descriptors, WordPress configuration, and the .NET application frameworks — Entity Framework, Dapper,
ASP.NET Core, Blazor, MAUI, WPF, WinUI and Avalonia. Rules ship in a **default profile** — the conventions and stylistic
checks stay off until `--all-rules` asks for them — because a report where every preference is an
issue buries the defects that matter.

The bar the engine is held to is precision: every rule is measured on somebody else's production
code in its own language before it is kept, a rule that produces noise is rewritten on the tree or
removed, and every false positive that was fixed is pinned by a regression test — see
[§8](#8-quality-bar).

---

## 1. Packages

| Project | Responsibility |
| --- | --- |
| `QualityGuard.Core` | Domain models, tokenizers, parsers, semantic model, taint analysis, duplication detection, rule framework and gate evaluator. |
| `QualityGuard.Sources.Sarif` | Reader and writer for **SARIF 2.1.0**: imports metrics from an existing report, exports findings and gate state. |
| `QualityGuard.Cli` | Executable entry point for pipeline jobs; explicit exit codes. |
| `QualityGuard.Mcp` | **Model Context Protocol server** (`net10.0`): exposes scans, the gate verdict and AI-oriented Markdown reports as MCP tools over stdio or Streamable HTTP for local agents (Claude Code, OpenCode, Codex, Copilot). |

The four projects ship as NuGet packages — `1.0.0` today —
via `scripts/publish-nuget.ps1`, which packs them in dependency order and pushes on demand.
The MCP server consumes the other three packages from NuGet and is fully standalone.

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

* **Syntax tree** — recursive-descent parsers for C#, VB.NET, Java, Go, JavaScript, TypeScript, PHP,
  Kotlin and Dart (one C-family parser with a dialect each) and an indentation-driven parser for
  Python. Everything else — Swift, Ruby, Rust, C/C++, shell, SQL — falls back to a generic structural
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

**3795 rules are loaded**, backed by **5861 catalog entries** (an entry either carries its own
detection or documents a rule implemented in code). Every rule ships an English name, message,
summary, *why is this an issue* and *how to fix*.

### Languages

Every language below is recognised by extension, tokenized, parsed and analysed. "Tree" says how much
structure the rules can rely on: a dedicated parser gives exact statement boundaries, the generic
structural parser recognises declarations, blocks and control flow, and configuration formats are
read as a tree of keys and blocks.

| Language | Code | Rules | Tree |
| --- | --- | --- | --- |
| Java | `JV` | 617 | dedicated parser |
| JavaScript | `JS` | 470 | dedicated parser |
| Python | `PY` | 478 | dedicated parser |
| C# / VB.NET | `CS` | 445 | dedicated parser |
| Kotlin | `KT` | 224 | dedicated parser (C-family dialect) |
| PHP | `PP` | 206 | dedicated parser |
| Terraform | `TF` | 148 | configuration tree |
| HTML | `HTML` | 139 | markup reader |
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
| Secrets (any language) | `SEC` | 31 | token scan over every file |
| C / C++ | `CC` | 16 | structural parser |
| Shell | `SH` | 12 | structural parser |
| SQL | `SQL` | 9 | structural parser |
| TypeScript-specific | `TS` | 9 | dedicated parser |
| XAML / WPF / WinUI / Avalonia | `XAML` | 8 | markup reader, joined to the class behind it |
| Scala | `SC` | 16 | dedicated parser (C-family dialect) |
| Razor / Blazor | `RAZ` | 4 | C# parser over the `@code` block, markup reader over the rest |
| Multi-language | `ALL` | 2 | whichever tree the file has |

TypeScript, Sass, SCSS, Less, JSX/TSX and VB.NET are analysed by the rules of the language they
extend, so their own row only counts what is specific to them.

### Razor and Blazor

A component is one class written across two files: `Counter.razor` holds the markup and an `@code`
block, `Counter.razor.cs` holds the rest as a partial class. QualityGuard reads it the way the
compiler does — the `@code` block is parsed as C# and every C# rule runs on it, while the markup is
read as markup. The two halves are joined by name, so a field declared in the code-behind and used
only from the markup counts as used, and the other way round.

Getting that wrong is expensive: parsing a whole `.razor` file as C# turns the prose in the markup
into expressions, and treating the file as pure markup makes every field of every component look
dead. Four rules are specific to components — a query-string parameter whose type the framework
cannot bind, a `[JSInvokable]` method that is not public, a query parameter in a component no route
reaches, and an event handler written as a lambda inside a markup loop.

### Frameworks

A .NET application is not written against the language, it is written against libraries, and the
mistakes that cost the most live there. These are read on the tree, with the receiver resolved where
the declaration is in the scan:

* **Entity Framework** — a query inside a loop, which asks the database once per item and only hurts
  once the data grows; changes saved per item instead of per batch; rows materialised and then
  filtered in memory; a synchronous call to the database inside a method written to be asynchronous.
* **Dapper and raw ADO** — a statement assembled from values instead of receiving them as parameters.
* **HTTP** — a client created per call, which reserves a socket for minutes after it is disposed and
  exhausts the machine's ports under traffic.
* **Blazor** — a parameter the framework cannot set or cannot bind from the query string, a method
  JavaScript is told to call and cannot, an `async void` handler whose failure takes the circuit down,
  a subscription the component never releases, a handler rebuilt for every row of a loop.
* **ASP.NET** — an API controller carrying the machinery for views it never renders, actions whose
  routes are all absolute, a route with no controller route to be relative to, a template written with
  a leading slash. And the checks every profile turns on: a `[Pure]` method that returns
  nothing, `[Flags]` members that overlap, an exception type left public, a lock taken on
  a string or on `this`, `new DateTime` without its kind, a `ToString` returning null.
  a backslash.
* **WPF, WinUI and Avalonia** — the same reading serves all three: a name that identifies two
  elements, a static resource key that resolves nowhere, an event bound to a handler no class
  declares, a two-way binding with no path, a credential written into the markup.

Security has its own set, read the same way. In code: a password salt or an initialisation vector
written into the source, a cipher left in codebook mode or with an attackable padding, a key
generated below what is worth generating, the secret that signs tokens committed with the code. In
infrastructure: storage a permission opens to everyone, the block on public access switched off,
versioning disabled, backups kept for less than a week, a service that answers anonymous callers, a
gateway route with no authorization — with the preflight route left alone, because that one is
supposed to be open.

### The default profile

A catalogue is not a profile. Established engines ship around half of their checks disabled out of
the box — method naming, magic numbers, metric thresholds, stylistic preferences — and QualityGuard
follows the same split. `Rules/DefaultProfile.cs` lists the rules that stay silent: they remain
loaded and documented, and run only when the scan asks for everything.

```bash
dotnet run --project src/QualityGuard.Cli -- --path ./src               # default profile
dotnet run --project src/QualityGuard.Cli -- --path ./src --all-rules   # conventions included
```

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

PHP also carries a WordPress set, described under *Descriptors and platform configuration*: five
rules that read the platform's own configuration file and nothing else, because three of them are
about a constant that is *missing* and would otherwise fire on every PHP file in existence.

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

### Mobile: Kotlin and Android

Kotlin has a dedicated parser — a dialect of the C-family one, on the TypeScript branch rather than
the Java one, because `fun f(a: Int): String` puts the type after the name — and carries **194
rules**: coroutines and dispatchers, the not-null assertion operator, `SharedPreferences` holding a
secret, and a full Android security set read on the tree.

* **Intents and receivers** — a broadcast sent without naming the permission its receivers must hold,
  a sticky broadcast (which the platform cannot protect at all), a receiver registered at run time
  that any application on the device can trigger.
* **Web views** — file, content and universal access enabled, JavaScript enabled for content that is
  not yours, and an application object handed to the loaded page as a bridge.
* **Keys and authentication** — a key generated in the hardware store without requiring the user to
  authenticate, a biometric prompt shown without a cryptographic object (so the result is a boolean
  somebody decides to trust), a local database encrypted with a key written in the source, an
  authenticated cipher reusing an initialisation vector taken from a literal.
* **Release builds** — the Gradle script itself is read: a release type that is debuggable, one that
  does not enable minification, and a build that switches dependency verification off. These only
  run where the module declares an application identifier, because a library has no release package
  to harden.

The manifest is read too, as XML — see *Descriptors and platform configuration*. The work that
mattered on Kotlin was precision rather than count: an extension function, a `@Composable`, a
trailing lambda and the word "token" in a parser were all being reported, and Jetpack Compose alone
accounted for hundreds of findings. See [§8](#precision-on-kotlin).

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

**Terraform — 148 rules, across the three major providers.**

* **Shared** — storage without encryption at rest, resources reachable from the whole internet,
  outdated TLS versions, logging switched off, policies granting every action to everyone, keys that
  are never rotated, short log and backup retention.
* **AWS** — buckets that do not enforce HTTPS-only access, public access blocks left open,
  unversioned buckets, security groups opening administration ports to `0.0.0.0/0`, databases
  reachable from the internet or unencrypted.
* **Azure** — full-control built-in roles handed out (`Owner`, `Contributor`, `User Access
  Administrator`), custom roles that allow every action over a whole subscription, resource-level
  administrator accounts, role-based access control switched off on clusters and key vaults, key
  vaults without purge protection, and services that run code without a platform-managed identity —
  which is what forces somebody to store a secret instead.
* **Google Cloud** — bindings that grant an administrator or owner role, `allUsers` and
  `allAuthenticatedUsers` on IAM bindings, object ACLs and BigQuery datasets, custom roles that
  accumulate write permissions or include the ones that let their holder impersonate another
  identity, App Engine handlers that accept plain HTTP, load balancer policies still offering broken
  cipher suites, buckets without versioning or uniform access, log buckets with a retention shorter
  than two weeks, audit configurations that exempt individual members, and legacy attribute-based
  access control on clusters.

**CloudFormation — 104 rules.** Templates are recognised by their content, not their extension, so a
`.yaml` template is read as a template and not as a Kubernetes manifest. Public access blocks with a
guard missing or switched off, API Gateway methods that change data and accept unauthenticated calls
(with sign-in, health and token endpoints deliberately left alone), backup retention shorter than a
week — read per resource type, so a read replica and an engine with continuous backup are not
reported.

**Kubernetes — 117 rules.** Privileged containers, privilege escalation, host namespaces, running as
root, missing resource requests and limits, writable root filesystem, unpinned images, wildcard RBAC,
added kernel capabilities, remote administration ports published by a container or a service, and
roles that allow creating an exec session inside somebody else's pod.

**Dockerfile — 120 rules.** Lower-case instructions, relative WORKDIR, duplicated CMD/ENTRYPOINT, ADD
for local files, the whole build context copied into the image, spaces around `=` in ENV/ARG, runs of
consecutive RUN instructions, unpinned base images, secrets in ENV — plus the security set: a debug
variable left on in the image that ships (read on the final stage only, because a builder stage is
discarded), a step running in the host's network namespace, a mounted secret readable by every
account in the build, a step with the builder sandbox disabled, and an executable copied in under a
non-root owner.

### Descriptors and platform configuration

A large part of what an application exposes is decided before any of its code runs, in files nobody
executes and everybody copies from the last project. These are read as element trees, and each rule
is bound to the file that gives its elements meaning.

* **Android manifest** — a package marked debuggable, clear-text traffic allowed, the platform backup
  left free to copy everything the application stores, a broadcast receiver reachable without a
  permission, a content provider guarding reading and writing with the same permission, a component
  with an intent filter that does not say whether it is exported.
* **Java EE descriptors** — a filter declared and mapped to no path, which is how an authentication
  or escaping filter ends up running on nothing at all; a default interceptor declared outside the
  descriptor the container reads it from; two validation forms sharing a name, where one silently
  wins.
* **ASP.NET `web.config`** — custom errors turned off, which answers a failed request with the stack
  trace and the physical path; response headers configured without the one that stops browsers
  guessing content types.
* **WordPress `wp-config.php`** — the built-in file editor left enabled, which turns an administrator
  account into code execution on the server; automatic updates switched off, on a platform whose
  fixes are published together with what they fix; unauthenticated database repair left on; outgoing
  requests unrestricted, so every installed plugin can call anywhere; unfiltered HTML allowed for
  anyone who can publish. These run on the configuration file itself and nowhere else.

### Python for the cloud

Infrastructure written from application code is analysed on the tree, in both shapes it is written
in: the construct of the deployment library, and the plain dictionary pasted in from a console.
Permission statements that allow every action, statements that grant an identity-delegating action
over every resource in the account, security group rules that open a remote administration port to
the whole internet, and a server bound to every network interface of its machine.

### Security coverage

**631 security rules.** Command injection, SQL injection, path traversal, open redirect, server-side
request forgery, unsafe deserialization, XML external entities, dynamic code execution, weak
cryptography (broken hashes, obsolete ciphers, ECB, reused initialisation vectors, predictable
randomness, weak key sizes), disabled certificate validation, cleartext transport, hardcoded
credentials and keys, permissive CORS, insecure cookies, missing security headers, privilege
escalation through IAM and custom roles, unauthenticated endpoints, mobile platform exposure
(receivers, providers, web view bridges, biometric prompts without a bound key), supply chain
(dependency verification disabled, remote artefacts without integrity checks) and infrastructure as
code (open CIDR blocks, unencrypted storage, wildcard policies, privileged containers, host
namespaces, disabled logging, short retention).

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

# evaluate overall and new-code coverage from the test runner's reports
dotnet run --project src/QualityGuard.Cli -- \
  --path ./src --coverage ./artifacts/lcov.info --base origin/main

# export the report as a page to keep and a Markdown file to paste
dotnet run --project src/QualityGuard.Cli -- \
  --path ./src --html ./artifacts/report.html --markdown ./artifacts/report.md
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
| `--html <out.html>` | Write the report as one self-contained page: styles, script and data inside the file. |
| `--markdown <out.md>` | Write the same report as Markdown, for a pull request, a chat window or an assistant. |
| `--new-code` | Map finding counts into the `new_*` rating metrics before evaluating the gate. |
| `--coverage <file>` | Read a coverage report (LCOV, Cobertura or JaCoCo) and feed the gate `coverage`, `line_coverage`, `branch_coverage` and the line/condition counts. Repeatable: reports from every test shard are merged; the tests' own files are left out, and the lines the sources themselves mark as not to be measured (see below) are removed. |
| `--base <ref>` | Base branch, tag, commit **or date** (`yyyy-MM-dd`) to measure new code against. With `--coverage`, git supplies the lines the current change added or rewrote and the `new_*` coverage metrics are computed on exactly those lines; that same count is recorded as `new_lines` and feeds the gate's 20-line activation floor. A date is resolved to the last commit strictly before it (a date with no matching commit falls back to `HEAD`). Without it `new_lines` and `new_coverage` stay unset, which the gate treats as passed. |
| `--fix-hints` | Print the remediation steps under every finding. |
| `--verbose` | Per-file metrics, taint flow steps and what the scan skipped. |
| `--rules` | List loaded rules and description coverage. |
| `--dump-ast` | Print the syntax tree of one file. |

### The exported report

Two formats, one set of numbers. `--html` writes a single page — stylesheet, script and data inside
the file — that opens on any machine with no server and no companion folder, which is what makes it
worth keeping or mailing. `--markdown` writes the same report as text: it survives being pasted into
a pull request, a chat window or a prompt, and an assistant asked to summarise a build reads it
without help.

**See one:** [`docs/report-example.md`](docs/report-example.md) renders here on GitHub, and
[`docs/report-example.html`](docs/report-example.html) is the page — GitHub shows its source, so open
it [rendered through htmlpreview](https://htmlpreview.github.io/?https://github.com/francescopaolopassaro/QualityGuard/blob/main/docs/report-example.html)
or download the file and open it locally. Both are produced by the command below from `samples/vuln`,
the deliberately defective sample tree in this repository, so anyone can reproduce them:

```bash
dotnet run --project src/QualityGuard.Cli -- \
  --path samples/vuln --html docs/report-example.html --markdown docs/report-example.md
```

```markdown
# QualityGuard report

**Quality Gate**: **FAILED**

---

## Summary

| Metric | Value |
|--------|-------|
| Files | 26 |
| NCLOC | 258 |
| Complexity | 51 |
| Duplicated Lines | 0% |
| Technical Debt | 6.7d (41.73%) |

## Quality Metrics

| Category | Count | Rating | Breakdown |
|----------|-------|--------|-----------|
| Bugs | 12 | D | Critical: 2, Major: 10, Minor: 0 |
| Vulnerabilities | 96 | E | Critical: 53, Major: 37 |
| Code Smells | 65 | C | Critical: 0, Major: 20, Minor: 45 |
| Security Hotspots | 1 | B | - |
```

The file continues with the gate conditions, the findings worth acting on — worst severity first,
with the data flow where taint analysis produced one — the rules that fire most, a per-folder
breakdown and a short list of what to do first. The page carries the same data with the counts as
cards and a panel per metric.

### Coverage exclusions

A line the team has explicitly told its coverage tooling to skip must not then count against the
gate, or the engine would argue with every other tool reading the same files. The same markers the
instrumented runners understand are read from the scanned sources and applied to the report before
the percentages are computed:

| How a line is marked out | Languages |
|---|---|
| `[ExcludeFromCodeCoverage]` / `[GeneratedCode(...)]` member attribute | C# |
| `@Generated` annotation | Java, Kotlin |
| `# pragma: no cover` | Python |
| `/* istanbul ignore next */` (also `c8`, `v8`), `/* istanbul ignore file */` | JavaScript, TypeScript |
| `# :nocov:` … `# :nocov:` | Ruby |
| `/** @codeCoverageIgnore */` (also `…Start` / `…End`) | PHP |
| `// LCOV_EXCL_LINE`, `// LCOV_EXCL_START` … `// LCOV_EXCL_STOP` (also `GCOVR_*`), `// coverage:ignore-line` / `-start` / `-stop` / `-file` | every language |

An attribute on a member removes every line the member occupies; `ignore file` removes the file
from the report altogether; a `START`/`STOP` (or `:nocov:`) pair removes the region between the
markers. `LCOV_EXCL_*` and `coverage:ignore-*` work in any language because the engine reads them
from the tokenizer's comment tokens, so a marker spelled inside a string literal never matches.

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

**645 tests** cover the parsers, the semantic model, taint, the scanner and rule precision. Every
false positive that was ever fixed has one of them, written next to the shape the rule must still
report, so precision cannot be lost again in silence.

### Noise, measured per language

Precision is not an opinion, so it is a number, measured on projects nobody here wrote: one or two
public repositories per language, plus two real applications the author owns — the harshest test,
because they are real legacy rather than a curated library.

| Project | Language | ncloc | Findings | Per 1k lines |
| --- | --- | ---: | ---: | ---: |
| a library of AWS CloudFormation templates | CloudFormation | 26 214 | 10 | **0.4** |
| a Google Cloud Terraform module library | Terraform | 50 085 | 90 | **1.8** |
| an AWS Terraform module library | Terraform | 5 475 | 22 | **4.0** |
| two public Terraform module libraries | Terraform | 55 560 | 112 | **2.0** |
| an Azure Terraform example library | Terraform | 22 146 | 193 | **8.7** |
| the public Kubernetes example manifests | Kubernetes | 5 743 | 142 | **24.7** |
| express | JavaScript | 14 707 | 56 | **3.8** |
| rails | Ruby | 281 755 | 1 343 | **4.8** |
| guzzle | PHP | 48 147 | 378 | **7.9** |
| gson | Java | 47 559 | 462 | **9.7** |
| okio | Kotlin | 44 514 | 569 | **12.8** |
| ripgrep | Rust | 42 211 | 663 | **15.7** |
| Alamofire | Swift | 26 592 | 369 | **13.9** |
| cobra, gin | Go | 30 723 | 488 | **15.9** |
| a Blazor application | C# | 58 468 | 876 | **15.0** |
| axios, nest | TypeScript | 36 073 | 648 | **18.0** |
| Newtonsoft.Json | C# | 126 652 | 2 330 | **18.4** |
| requests, flask, a private application | Python | 42 955 | 859 | **20.0** |
| a WebForms application from 2010 | C# | 152 633 | 8 522 | **55.8** |
| scalaz | Scala | 48 758 | 103 | **2.1** |

Every row is one scan per language, narrowed to that language's extension. The Scala row is a gap, not
a triumph: there is no dedicated parser for it yet, so no rule reaches those 48 717 lines. Rust is in
the table because the generic parser carries the shared rules there, not because the language has its
own.

**A repository of examples is not a repository.** The two highest infrastructure rows above are
collections of small samples: every example declares one virtual machine, one pod, one bucket, so
anything a rule asks of a resource is asked once per file. The same rules on a real deployment
repository land an order of magnitude lower, because most of the file is the part that was already
configured properly.

**Scan the whole project, not one extension.** Narrowing a scan to `**/*.cs` leaves the templates out,
and a field a component only touches from its markup then reads as unused — on the Blazor application
above, doing that produced 570 findings that all went away once the `.razor` files were in the scan.

The last row is the point of the table rather than an embarrassment: **density measures the code, not
the engine**. That application really does carry a thousand trivial properties wrapping a field, eight
hundred blocks of commented-out code and hundreds of dead stores — a sample read by hand puts the
false positives there at roughly one in ten. What the engine is judged on is that ratio, not the size
of the number.

### What a judged sample says today

Density is not precision, so precision is read rather than counted. On the Java library above, a sample
drawn per rule and read line by line held **12 false positives out of 24**. None of them came from the
newest rules: they came from old families with high volume, and each one turned into an engine fix —
a parser that lost the rest of the file on `f(in)` because `in` is a C# argument modifier and not a
Java one, another that read `return ArrayList::new;` as a return followed by two statements, catalogue
rules matching their pattern inside comments, a one-character literal typed as a string so `c != 'Z'`
became a comparison between unrelated types.

After those fixes the same sample holds **2 false positives out of 18**, and the library went from 685
findings to 376 without losing a true one. That ratio — not the size of the density column — is what
the engine is judged on.

### Measured against an annotated corpus

Coverage is the other half, and it is measured against corpora somebody else annotated for their own
engine, where every defective line carries a marker:

| corpus | annotated files | marked lines | lines reported |
| --- | ---: | ---: | ---: |
| Java | 1 022 | 10 320 | **46.3%** |
| Python | 590 | 6 427 | **41.1%** |

`tools/compare_expectations.py` produces both numbers, and the findings that land on unmarked lines are
listed to be read rather than counted: the two catalogues do not carry the same rules, and a file
written to exercise one check contains other real defects nobody annotated.

### Coverage is read, not computed

The engine does not measure code coverage: it reads the report the test runner already writes — lcov,
Cobertura or opencover — applies the exclusions and aggregates. That path is verified end to end: an
lcov written by hand with 13 covered lines out of 20 and 2 conditions out of 6 comes back as 57.7%
overall, 65.0% line and 33.3% branch, which is the arithmetic on paper.

### How the false-positive rate is measured

Density and precision are different questions, and only the second one judges the engine. Precision
is answered by reading a sample: findings are drawn per rule in proportion to how much each one
contributes to the report — a rule that fires a thousand times decides how the report reads, one that
fires twice does not — and each drawn finding is read against its own source line and marked true or
false. The ratio, with the interval the sample size supports, is the number.

Choosing what to work on next uses the same discipline. Rules are ranked by the signals that have
actually caught a defect in the past: findings per thousand lines, how far a single file dominates a
rule's output, how often the same sentence repeats, how often a finding lands on a line another rule
already took, and how much of the output falls in generated or vendored code. The rule at the top of
that list is opened first, its findings are read, and the family is either rewritten on the syntax
tree or removed.

Two measures moved every language at once. The first is a cap on how many times a single rule may
speak about one file: the twentieth finding carries the total and the rest are left out. The second
is the default profile — the conventions the reference engines ship disabled are disabled here too,
which is why the naming and magic-number rules no longer dominate a report.

### What reading their implementation gives that guessing does not

Every entry below is a condition the reference engines have and this one did not, found by reading
their check after a sample had shown the false positive:

* **an unused parameter** is reported only on a private, top-level or anonymous function — a
  signature somebody else can call is not a decision that file gets to revisit;
* **a duplicated literal** needs three occurrences and five characters, and never counts in tests;
* **a magic number** excludes −1, 0, 1, anything inside an annotation, `hashCode`, and above all a
  literal that already initialises a named constant;
* **a `when` over a sealed hierarchy** is already exhaustive, so asking it for an `else` asks for a
  branch the compiler calls unreachable;
* **an infinite loop** is only the one no `break`, `return` or `throw` ever leaves;
* **an empty catch** in `try { x; fail() } catch {}` is how a test states its expectation.

```bash
dotnet build QualityGuard.sln
dotnet test    # parsers, semantics, taint, scanner, rule precision, catalogue shape
```

### Measured against the reference engine's own expectations

Analyzer projects ship test corpora whose defective lines are annotated — a comment on each line that
must be reported. That is a ground truth written by someone else, for a different engine, without
any knowledge of this one, which makes it a usable instrument:

It reports **recall** (how many expected lines QualityGuard finds), **precision** (how many of its
findings land on an expected line), and the findings on unannotated lines — meant to be read rather
than counted, since the two catalogues do not coincide and a file written to exercise one check
usually contains other defects nobody annotated.

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

### Where the false positives come from

Counting the rules by how they are implemented settles the question:

| implementation | rules | share of findings on production code |
| --- | --- | --- |
| syntax tree, semantic model, taint | 276 | 55% |
| token scanning | 409 | |
| line scanning | 60 | **45%** |
| catalogue entry with only a line pattern | 181 | |

Six hundred and fifty rules out of nine hundred are heuristics, and they produce nearly half the
findings. Every false-positive family closed so far came from that half, and they fail in the same
three ways: a **substring** taken for a word (`0px` inside `40px`, `e.ToString()` inside
`base.ToString()`), a **name** taken for a type (`_service.DeleteAsync` read as an HTTP call), and a
**line** taken for a statement (a selector without the blocks it is nested in).

So the programme is to convert them, ordered by how much noise each one makes on real code rather
than by how easy it is. Nothing new is written as a pattern any more: a rule gets the tree, the
semantic model and the taint, or it does not get written.

The conversions are worth reading because each one shows what the tree knows that a line does not:

- *Asynchronous methods should be named accordingly* was a regular expression over the line. On the
  tree it can tell an override from a declaration, see that a method has no body, and know that a
  method carrying an attribute is named by the framework rather than by its author. 484 findings
  became 231, and the ones that went were all correct code.
- *A collection should not change while it is being walked* looked for `foreach` and then for any
  `.Add(` in the tokens that followed, which reported `anomalie.Add(...)` inside a loop over
  `comuniSezioni`. It now takes the collection the loop actually walks and compares it with the
  receiver of the call.
- *Collections exposed by properties should be read-only* matched a one-line pattern, so it missed
  every property written over two lines and could not see a `private set`. The parser was keeping the
  accessors but throwing their modifiers away; it keeps them now.

Converting also found a regression this work had introduced two hours earlier: the guard that stops
the parser reading an unclosed `[` as an attribute list was returning at the first `)`, and an
attribute with arguments — `[HttpGet("by-verbale/{id}")]`, which is every controller action ever
written — has one. Every action in the scanned code had lost its attributes.

### What a sample found in somebody else's library

The second judged sample was drawn from a different application, and almost every row of it was
Bootstrap. `app.css` at fifteen thousand lines, `_buttons.scss`, `_variables.scss`, a folder called
`bootstrap-5.3.0`: the report was describing a library the team had downloaded, and its own code was
a tenth of what was being counted.

The scanner already refused `node_modules` and minified bundles for exactly this reason, so the gap
was in the disguises it did not know. It now also refuses a directory named after a library and its
version, a directory named after a library the industry has one of — bootstrap, jQuery, DevExpress,
Font Awesome, Kendo and the rest — and a stylesheet or script that is a build artefact, which gives
itself away by running to thousands of lines or by carrying the library's banner at the top. That one
project went from 71,845 counted lines to 7,548, and from 6,592 code smells to 583.

The same sample found two rules wrong in the same way, and it is worth naming because it is the
commonest mistake in this codebase: **searching for a substring**. "Omit the unit on zero values"
looked for the text `0px`, which is inside `40px` and `1280px`; more than half its findings were
ordinary lengths. And "a selector should be defined once" compared the text of a selector without the
blocks it is nested in, so every `&.hidden` in a stylesheet looked like a duplicate of every other
one — seventy findings, all of them wrong.

### One line of C# that hid a whole file

Chasing the last few lines of that gap turned up something worth more than the lines. A finding the
reference reported sat in a `catch` block this engine could not see — and the reason was that the
file had no `catch` in its tree at all. Nor a `try`. From one line onwards the parser was reading
Italian prose as code, because the tokenizer had lost its place:

```csharp
$"(fase corrente: {(faseCorrenteNome is not null ? $"\"{faseCorrenteNome}\"" : "sconosciuta")})"
```

An interpolated string, holding an expression, holding another interpolated string, holding escaped
quotes. The tokenizer ended the outer literal at the first quote inside the braces and read the rest
of the file as source. Every rule below that line was blind, in every file that contains such a
construct — and one is enough.

Two things were wrong underneath. `$"` was not in the list of C# string forms at all, so it was read
as a `$` symbol followed by an ordinary literal; and `IsVerbatim` was defined as "the prefix is
longer than one character", which made `$@"` verbatim — correct — but would have made `$"` verbatim
too, which is not. A verbatim literal takes backslashes literally; an interpolated one does not.

Now the reader follows the braces: inside a hole the quotes belong to the expression, and the literal
ends where the braces are balanced again. `{{` still prints a brace rather than opening a hole. The
`$` is still emitted as its own token, because that is how the parser recognises an interpolated
string, and the tests that pin that behaviour keep passing.

The file that produced nothing now parses, and the complexity this engine measures for that project
went up by a hundred points — code that was there all along and was never read.

### Running the other analyzer on the same code

The two instruments above measure against a catalogue and against a reader. The third one measures
against the other analyzer, on the same source, and it is the only one that answers "are we there
yet" directly.

A reference analyzer for .NET ships as a compiler package, so it can be run without a server: copy
the project, add the package through a `Directory.Build.props`, build, and collect the warnings.
Then run this engine over the same projects and compare where the two land.

Two things have to be checked before the numbers mean anything, and both changed the answer:

- **The package is not the whole profile.** The security-hotspot rules are not in it: `new Random()`,
  `MD5.Create()` and a cookie without `Secure` produce nothing, and they still produce nothing when
  the `.editorconfig` enables them by id. So the comparison covers bugs and code smells, and says
  nothing about the security families.
- **The two sides do not see the same files.** Of 292 source files in those projects the engine reads
  205: it refuses generated migrations and designer files, which the compiler happily analyses. Nine
  of the findings that looked like a gap were in exactly those, so they are excluded from both sides.

With both accounted for, on six production projects of one application:

| | Reference | QualityGuard |
| --- | --- | --- |
| findings | 132 | 434 |
| distinct lines | 124 | 405 |
| files touched | 36 | 70 |
| distinct rules that fired | 36 | 69 |

**95% of the lines the reference reports are reported here too**, up from 42% when the comparison was
first run. The number is sensitive to how close two findings have to be to count as the same place —
88% at the exact line, 95% within one, 96% within three — so one line is the figure quoted, and the
sensitivity is quoted with it. At file level, 33 of the 36 files it flags get attention here too.

Closing that gap produced twenty-one rules, each written after reading what the other analyzer saw and
this one did not: type names with an acronym buried in the middle, `new Guid("0000…")`, a private
class that is not sealed, a derived type that adds nothing, `First()` on an indexed collection,
overloads written apart, a host started with a blocking call, an action that returns a value while
declaring `IActionResult`, a field that is really a local, a private member nothing reads, a loop
whose body is one condition, an incomplete disposable, a switch whose arms hand back what they
matched, a static constructor that only assigns, a failure logged and rethrown, a property nothing
writes, a function whose answer every caller discards, and a bound request field that cannot tell
absent from zero.

It also found gaps in rules that already existed. The dead-store rule only knew about two writes in a
row; widened to cover a value written and never read again, it immediately found a real defect — a
seeder whose `else` branch loads four records from the database and never uses them, because the code
that would use them is in the other branch. And the rule about awaiting a query never fired on
`context.Comuni.ToList()`, because it looked for `_context` with an underscore; it now reads the root
of the chain, which tells `context.Comuni.ToList()` apart from `items.Select(…).ToList()`.

**Four of the six remaining differences are deliberate, not gaps.** The reference reports a name
like `AffissioneDatiDTO`; this one does not, because an acronym at the end of a name hides nothing
and naming DTOs that way is a decision a codebase makes once — it was 130 findings on one project. An
acronym in the middle is still reported, because `DocDocumentiWKFModelliFasi` does have to be read
twice. The advice "initialise the field where it is declared" is withheld when the static constructor
wraps the work in a `try`, because there it cannot be followed. And `== false` is left alone when the
operand's type cannot be resolved, because on a `bool?` the suggested `!x` does not mean the same
thing. Silence chosen for a reason costs coverage and is worth it; the two that are left are ordinary
gaps.

### The same comparison, on JavaScript

The reference publishes the findings it expects on a hundred open-source projects, file by file and
line by line, with the sources pinned to an exact revision. That is a ground truth nobody here chose,
and running against it says plainly where this engine stands.

It also has to be read with one correction. The published expectations come from running *every*
rule, and the default profile enables 459 of 583. The five rules that dominated the first gap list —
braces around a one-line body, object shorthand, the ternary operator — are not among them: they are
house style, switched off unless a team asks for them. Measuring against rules nobody enables would
have flattered the number and pointed the work in the wrong direction. Both were written and are kept
switched off for the same reason.

Against the default profile, on the projects whose sources are available:

| project | reference | here | of its lines covered |
| --- | --- | --- | --- |
| backbone | 86 | 407 | 41% |
| jquery | 366 | 895 | 9% |

That is the honest position: on C# the engine reaches 95% of what the reference reports; on
JavaScript it does not, and it says more than the reference does while covering less of it. The gap
list is ranked by volume and worked from the top — the first rule taken from it, a value stored in
the middle of an expression, was 107 of the missed lines on its own.

### Two questions, two instruments

The table above answers one question: how much of another catalogue does this engine find. It cannot
answer the other one — of the findings it produces, how many are true — and reading it as if it could
is the most tempting mistake available here.

The reason is in how the corpus is built. Each file exercises one check, and only the lines for that
check carry a marker. A file written to test "empty method body" also contains an unused variable, a
magic number and a catch that swallows everything, all real, none marked. Every one of them counts
against precision in that table. The number is a measure of overlap with someone else's catalogue,
not of correctness.

Correctness has to be judged by reading the code, so there is a second instrument:

It draws a sample weighted by how much each rule contributes to the report — a rule that fires a
thousand times decides how the report reads, one that fires twice does not — and writes each finding
with the lines around it. A person marks `ok` or `fp`, and the tool reports precision with the
interval the sample size actually supports.

The first judged sample, forty findings on a 58,000-line production application, came out at **78%**,
and it named the defect that mattered: four of the seven wrong findings were Blazor event handlers
reported as unreachable code. The engine indexes what the C# files reference; the handlers are named
in the markup, `@onclick="SalvaModifiche"`, which no syntax tree of ours ever saw. Templates are now
indexed for the names they mention — Razor, Blazor, Vue, JSP, XAML and the rest — and that family
went from 278 findings to 11 on the same repository.

That is how the number goes up: draw a sample, read it, fix the family the wrong ones belong to,
draw again. Each pass costs an hour and moves a whole category, because false positives arrive in
families and almost never one at a time.

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

### One defect, one finding

A reader who is told the same thing three times stops reading. A dedicated pass runs the
engine over a corpus and reports the rule pairs whose findings land on the same line:

On the Java corpus it found twenty such pairs, and on the C# one forty-five, and the largest was four rules for one defect: a call
to `System.out` was reported by a shared analyzer and by three separate ported entries, 1,076 times
each. Seven rules were retired in favour of the one that says it best. Retirement is recorded in the
catalogue rather than hidden: the entry keeps its documentation and takes `status: superseded` with
`superseded_by`, so the identifier keeps its meaning and is never handed to a different check. The
validator enforces that pairing.

Nineteen rules have been retired this way so far. The four most recent came out of the
infrastructure work: two Kubernetes rules whose replacements read the same pod specification — one
about host namespaces, one about added capabilities — one Terraform rule about bucket versioning that
read the file as
lines — any occurrence of the word `versioning` anywhere silenced it for every bucket in the file —
and one Kotlin rule that reported anything named `allowFileAccess` with the word `true` within four
tokens, which flags the check that turns the setting *off* as readily as the assignment that turns it
on. Three more said the same thing about
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

