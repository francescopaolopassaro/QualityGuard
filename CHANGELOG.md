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
* Quality improved on real corpora: PHP guzzle 7.9→5.3/1k (−33%), Python flask 15.0→12.8/1k (−15%), C# Newtonsoft stable at 20.4/1k.

### Fixed

* Kotlin annotations detached by ASI reconstruction; base types after `:` were skipped entirely; extension-function receivers lost; object expressions parsed as orphan identifiers.
* PHP echo/print operands disappeared from the tree.
* Java assert parsed as identifier + stray statements.
* Cookie flag rule fired on every file even when setSecure/setHttpOnly were called on adjacent lines.

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