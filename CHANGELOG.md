# Changelog

All notable changes to QualityGuard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-08-26

### Added

* **Vendor marking**: `--vendor <glob>` flags third-party files so rules stay silent on code nobody can change; metrics and project index remain intact.
* **OWASP Top 10 catalog** (`owasp.yaml`): 15 executable security rules covering A01–A10 with taint-gated detection — command injection, SQL injection, XSS, SSRF, open redirect, path traversal, deserialization, weak crypto, predictable randomness, log injection.
* **Multi-language semantic model**: source and sanitizer recognition extended to ASP.NET Core (`HttpContext.Request.Query/Form/Headers`), Flask (`flask.request.args/form/values`), Django (`request.GET/POST/FILES`), Express (`req.query/params/body`), Go net/http (`r.URL.Query`, `r.FormValue`), plus OWASP-recommended encoders (`encodeForSQL`, `encodeForHTML`, `canonicalize`) and security wrapper classes.
* **Flow-sensitive taint clearing**: a variable whose LAST assignment routes through any method call or literal is cleared from the tainted set — eliminating false positives where values are sanitized between source and sink.
* **Central flow gate in RuleEngine**: security findings on lines without untrusted input evidence are suppressed when taint data exists for the file.
* **Parser modernization**: Java `record` (components as ParameterList), `sealed`/`permits`, switch-arrow expressions (`case X -> expr`), text blocks (`"""` delimiter), `assert` statements (condition + message), Python `async def` modifier, Kotlin extension-function receivers, Kotlin object expressions, PHP echo/print operands.
* **New rule families**: Kotlin idioms (10 rules), C# contracts (19 rules: SQL/command/header injection, format strings, logging templates, Azure Functions statelessness, cookie security), PHP security shapes (4 rules).
* **ASVS + CWE retro-tagging**: 425+ security rules tagged with ASVS chapters and CWE identifiers.
* **OWASP Benchmark scorer**: repeatable script measuring recall, precision, accuracy and false-positive rate on the 2,740-case benchmark corpus.

### Changed

* Rule count grew from 3980 to **4083** across 27 languages.
* Test suite grew from 645 to **758 tests**, all passing.
* Security rule count grew from 639 to **657**.
* Quality improved on real corpora: PHP guzzle 7.9→5.8/1k (−27%), Ruby rails 4.8→2.2/1k (−54%), Python flask 15.0→14.4/1k (−4%), C# Newtonsoft stable at 21.9/1k.

### Fixed

* Kotlin annotations detached by ASI reconstruction; base types after `:` were skipped entirely; extension-function receivers lost; object expressions parsed as orphan identifiers.
* PHP echo/print operands disappeared from the tree.
* Java assert parsed as identifier + stray statements.
* Cookie flag rule fired on every file even when setSecure/setHttpOnly were called on adjacent lines.
* **Rust SSRF false positives** (`QG-RS-SEC-0009`): matched `.get()/.post()/.put()/.delete()` on any receiver (HashMap, Vec, Captures); now scoped to `reqwest::` HTTP client calls only. Rust vulnerabilities dropped from 70 to 6 (−91%).
* **Rust path traversal false positives** (`QG-RS-SEC-0008`): flagged every `fs::open`/`File::open`/`PathBuf::from`; now requires a tainted identifier in the arguments.
* **PHP backtick false positives** (`QG-PP-SEC-0003`): flagged backtick characters inside docblock comments and `//` lines; comment lines are now excluded. PHP vulnerabilities dropped from 37 to 28 (−24%).
* **Ruby heredoc backtick false positives** (`QG-RB-SEC-0001`): backticks inside heredoc content were tokenized as standalone symbols and flagged as command substitution; heredoc context is now detected and skipped.
* **PHP regex hex escape false positives** (`QG-PP-BUG-0075`): `RegexPattern.ReadClass()` did not handle `\xNN`/`\uNNNN` escapes inside character classes, so `\x21-\x7E` was read as three separate items causing phantom duplicate dash findings. Rewrote with a shared `ReadAtom()` helper that correctly forms ranges. Also fixed PHP single-quoted strings stripping backslashes — added `PreserveBackslashes` flag to `StringDelimiter` so `'\x00'` stays as `\x00` instead of becoming `x00`. PHP BUG-0075 dropped from 6 to 0 on guzzle.
* **Ruby self-assignment false positives** (`QG-RB-BUG-0028`): `@var = var` was flagged as assigning a variable to itself, but in Ruby the `@` sigil arrives as a separate sibling AST node — the existing check only looked at the assignment child's tokens and missed it. Added `HasSigilPrefix()` that inspects preceding siblings for `@` or `$`. Ruby BUG-0028 dropped from 18 to 0 on rails.

### Deprecated

* Three PHP rules retired after benchmark sampling showed irreducible noise.

## [1.0.0] - 2026-08-20

### Added

* **Model Context Protocol server** (`QualityGuard.Mcp`, `net10.0`): a
  standalone MCP server exposing code scans, Quality Gate evaluation and
  AI-oriented Markdown reports as MCP tools (`analyze`, `list_languages`,
  `list_rules`, `rule_details`, `read_sarif`, `quality_report_markdown`),
  over stdio or Streamable HTTP, for local agents (Claude Code, OpenCode,
  Codex, Copilot).
* Standard repository files: `SECURITY.md` (vulnerability reporting) and
  `CHANGELOG.md`.

### Changed

* All four projects ship as NuGet packages at `1.0.0` via
  `scripts/publish-nuget.ps1` (packed in dependency order, pushed on demand).
* The MCP server now consumes `QualityGuard.Core`, `QualityGuard.Sources.Sarif`
  and `QualityGuard.Cli` **from NuGet** (`PackageReference`) instead of
  `ProjectReference`: the server is fully standalone.
* Package metadata is shared through `src/Directory.Build.props`: version,
  authors, license file, readme and package icon for every project.

## [0.9.0] - 2026-08-17

### Added

* First published release of all four packages to NuGet:
  `QualityGuard.Core`, `QualityGuard.Sources.Sarif`, `QualityGuard.Cli` and
  `QualityGuard.Mcp`.
* `scripts/publish-nuget.ps1`: builds and packs the four projects in
  dependency order, skips packages already present on the feed and pushes on
  demand (requires an API key).

[1.0.1]: https://github.com/francescopaolopassaro/QualityGuard/releases/tag/1.0.1
[1.0.0]: https://github.com/francescopaolopassaro/QualityGuard/releases/tag/1.0.0
[0.9.0]: https://github.com/francescopaolopassaro/QualityGuard/releases/tag/0.9.0