# Changelog

All notable changes to QualityGuard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/francescopaolopassaro/QualityGuard/releases/tag/1.0.0
[0.9.0]: https://github.com/francescopaolopassaro/QualityGuard/releases/tag/0.9.0