# QualityGuard report

**Quality Gate**: **FAILED**
**Generated**: 2026-08-19 14:48:29

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

## Quality Gate Conditions

| Metric | Actual | Expected | Status |
|--------|--------|----------|--------|
| new_coverage | not measured | < 80 |  Failed |
| new_duplicated_lines_density | not measured | > 3 |  Failed |
| new_security_hotspots_reviewed | 0 | < 100 |  Failed |
| new_reliability_rating | not measured | > 1 |  Failed |
| new_maintainability_rating | not measured | > 1 |  Failed |

## Issues worth acting on

### BLOCKER: QG-PY-SEC-0006

> **Do not hard-code credentials.**

**File**: `demo.py:9`

---

### BLOCKER: QG-PY-SEC-0044

> **The command goes through a shell, so metacharacters in it are interpreted.**

**File**: `demo.py:5`

---

### BLOCKER: QG-RB-SEC-0006

> **Do not hard-code credentials.**

**File**: `demo.rb:6`

---

### BLOCKER: QG-RS-SEC-0004

> **Do not hard-code credentials.**

**File**: `demo.rs:21`

---

### BLOCKER: QG-CS-SEC-0093

> **The command is built by joining a value into the text, so whatever that value contains becomes part of the statement — a quote ends the string and the rest is executed. Pass the value as a parameter and leave the text alone.**

**File**: `AspNetDemo.cs:16`

---

### BLOCKER: QG-CS-SEC-0038

> **This raw SQL statement is built by concatenation or interpolation instead of parameters.**

**File**: `AspNetDemo.cs:16`

---

### CRITICAL: QG-CC-SEC-0001

> **Make sure this OS command is not built from user input.**

**File**: `demo.c:7`

---

### CRITICAL: QG-CC-SEC-0003

> **gets cannot bound the input buffer and can overflow it.**

**File**: `demo.c:9`

---

### CRITICAL: QG-CC-SEC-0004

> **Make sure the format string is not built from user input.**

**File**: `demo.c:10`

---

### CRITICAL: QG-CS-SEC-0001

> **Sanitize arguments passed to Process.Start.**

**File**: `Demo.cs:9`

---

### CRITICAL: QG-CS-SEC-0002

> **Use parameterized queries to prevent SQL injection.**

**File**: `Demo.cs:11`

---

### CRITICAL: QG-CS-SEC-0004

> **Hardcoded credentials must not be committed.**

**File**: `Demo.cs:13`

---

### CRITICAL: QG-GO-SEC-0001

> **Do not build shell commands from dynamic input.**

**File**: `demo.go:11`

---

### CRITICAL: QG-GO-SEC-0002

> **Use parameterized queries to prevent SQL injection.**

**File**: `demo.go:13`

---

### CRITICAL: QG-JV-SEC-0002

> **Make sure the arguments passed to this OS command are not user-controlled.**

**File**: `demo.java:6`

---

### CRITICAL: QG-JV-SEC-0003

> **Replace this weak cryptographic algorithm 'MD5' with a strong one.**

**File**: `demo.java:7`

---

### CRITICAL: QG-JV-SEC-0004

> **Make sure this SQL query is not vulnerable to SQL injection.**

**File**: `demo.java:9`

---

### CRITICAL: QG-JV-SEC-0005

> **Define this credential through configuration or an environment variable.**

**File**: `demo.java:10`

---

### CRITICAL: QG-JS-SEC-0001

> **Do not evaluate arbitrary code with eval.**

**File**: `demo.js:4`

---

### CRITICAL: QG-JS-SEC-0002

> **Do not execute operating system commands built from a dynamic argument.**

**File**: `demo.js:3`

---

### CRITICAL: QG-JS-SEC-0004

> **Do not concatenate user-controlled values into SQL statements.**

**File**: `demo.js:7`

---

### CRITICAL: QG-KT-SEC-0001

> **Random values must not be used for security-sensitive operations.**

**File**: `demo.kt:2`

---

### CRITICAL: QG-KT-SEC-0001

> **Random values must not be used for security-sensitive operations.**

**File**: `demo.kt:5`

---

### CRITICAL: QG-KT-SEC-0002

> **Make sure the arguments passed to this OS command are not user-controlled.**

**File**: `demo.kt:6`

---

### CRITICAL: QG-KT-SEC-0005

> **Define this credential through configuration or an environment variable.**

**File**: `demo.kt:8`

---

### CRITICAL: QG-PP-SEC-0001

> **Do not evaluate arbitrary code.**

**File**: `demo.php:3`

---

### CRITICAL: QG-PP-SEC-0003

> **Sanitize arguments passed to OS command execution.**

**File**: `demo.php:4`

---

### CRITICAL: QG-PP-SEC-0005

> **Hardcoded credentials must not be committed.**

**File**: `demo.php:6`

---

### CRITICAL: QG-PP-SEC-0010

> **Unsafe deserialization can lead to code execution.**

**File**: `demo.php:7`

---

### CRITICAL: QG-PY-SEC-0002

> **Do not build shell commands from dynamic input.**

**File**: `demo.py:4`

---

### CRITICAL: QG-PY-SEC-0002

> **Do not build shell commands from dynamic input.**

**File**: `demo.py:5`

---

### CRITICAL: QG-PY-SEC-0003

> **Unsafe deserialization may allow remote code execution.**

**File**: `demo.py:6`

---

### CRITICAL: QG-PY-SEC-0004

> **Use parameterized queries to prevent SQL injection.**

**File**: `demo.py:8`

---

### CRITICAL: QG-PY-SEC-0040

> **Assertions are removed when the interpreter runs optimised, so this check can disappear.**

**File**: `demo.py:10`

---

### CRITICAL: QG-RB-SEC-0001

> **Do not invoke shell commands with dynamic arguments.**

**File**: `demo.rb:2`

---

### CRITICAL: QG-RB-SEC-0003

> **Unsafe deserialization may allow remote code execution.**

**File**: `demo.rb:4`

---

### CRITICAL: QG-RS-SEC-0002

> **Use parameterized queries to prevent SQL injection.**

**File**: `demo.rs:19`

---

### CRITICAL: QG-SH-SEC-0001

> **Do not evaluate dynamic shell code.**

**File**: `demo.sh:2`

---

### CRITICAL: QG-SH-SEC-0003

> **Do not pipe downloaded scripts directly into a shell.**

**File**: `demo.sh:3`

---

### CRITICAL: QG-SH-SEC-0005

> **Hardcoded credentials must not be committed.**

**File**: `demo.sh:4`

---

_88 more findings of the same kind are in the full report._

## Most Frequent Rules

| Category | Rule ID | Name | Count |
|----------|---------|------|-------|
| Code Smells | `QG-CS-SML-0021` | This local variable is assigned but never used. | 7 |
| Code Smells | `QG-CS-SML-0499` | 'md5' is assigned but never read; remove it or use the value it holds. | 7 |
| Bugs | `QG-RS-BUG-0007` | This unwrap panics when the value is absent or the operation failed. | 4 |
| Code Smells | `QG-CS-SML-0475` | 'DocumentService' sits in the global namespace, where its name has to be unique across ... | 4 |
| Vulnerabilities | `QG-TF-SEC-0064` | This range lets every address on the internet reach the resource. Narrow it to the netw... | 3 |
| Vulnerabilities | `QG-CS-SEC-0001` | Sanitize arguments passed to Process.Start. | 2 |
| Vulnerabilities | `QG-CS-SEC-0002` | Use parameterized queries to prevent SQL injection. | 2 |
| Vulnerabilities | `QG-CS-SEC-0003` | Replace weak cryptographic primitives with modern algorithms. | 2 |
| Vulnerabilities | `QG-CS-SEC-0004` | Hardcoded credentials must not be committed. | 2 |
| Code Smells | `QG-JV-SML-0460` | 'd' is assigned but never read; remove it or use the value it holds. | 2 |

## Folder Breakdown

| Folder | Files | NCLOC | Bugs | Vuln | Smells |
|--------|-------|-------|------|------|--------|
| `vuln` | 20 | 190 | 8 | 84 | 39 |
| `dotnet` | 4 | 50 | 4 | 12 | 22 |
| `crossfile` | 2 | 18 | 0 | 0 | 4 |

## What to do first

- **Reliability first**: 12 bugs are waiting, and the critical and major ones are the ones users meet.
- **Security**: 53 critical vulnerabilities are open. Nothing else in this list comes before them.
- **Technical debt** stands at 41.73% of the effort it took to write the code. Plan the repayment rather than discovering it.

---

*Report generated by QualityGuard*
