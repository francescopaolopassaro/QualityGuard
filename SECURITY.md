# Security Policy

## Reporting a vulnerability

If you find a security issue in QualityGuard — a rule that misses a real
defect, a false positive that could block a pipeline, a crash on malicious
input, or something in the SARIF or MCP surface — please report it privately
before sharing it anywhere else.

**Do not open a public issue.** Send the details by email to
`francesco.paolo.passaro@outlook.com` with the subject
`[QualityGuard Security] <short description>`.

Please include:

* the affected version (package version or commit);
* the input that triggers the problem (a source file, a SARIF report, a
  coverage report, an MCP request), reduced to the smallest case that
  reproduces it;
* what you expected and what happened instead;
* anything unusual in the output (stack traces, wrong exit codes, leaked
  content).

You will receive an acknowledgement within 3 business days and a first
assessment — confirmed, under investigation, or declined — with an expected
timeline when applicable. Please give the project a reasonable window before
disclosing publicly.

## Security model

QualityGuard is a **stateless, in-memory analysis tool**:

* it never communicates with a server, does not collect telemetry and does
  not write outside the paths it is asked to write to;
* it runs arbitrary analysis over the *input* you give it, so treat source
  trees, SARIF reports and coverage reports like any untrusted input: scan
  files from sources you already trust and validate anything you feed it;
* the SARIF writer and the Markdown/HTML reports produce output files only at
  the paths you request;
* the MCP server binds to localhost by default and is intended for local
  agents; do not expose it to a network you do not control.

Reported findings are advisory: the tool never modifies your code.

## Supported versions

Security fixes are applied to the latest release and, where practical, back
ported to the most recent previous major version. Only the latest release is
guaranteed to receive fixes.

## Scope

Included: the engine, the rules, the SARIF reader/writer, the coverage
reader, the package build scripts and the MCP server.

Out of scope: anything that is a **misconfiguration or unsafe use of the
included libraries** — for example a scan of an untrusted tree is by
definition "running the tool", and a wrong report because the input was
malformed is a robustness issue to report under the same policy, not a
platform vulnerability.