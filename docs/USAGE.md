# AI Tools: Usage Guide

Universal code review and security analysis toolkit for **Go, Rust, Swift, Shell, Python, JavaScript, C, C++, Docker**.

## Quick start

    curl -L -o /tmp/aitools https://github.com/PavelNeyman/ai-tools/releases/latest/download/aitools-linux-amd64
    chmod +x /tmp/aitools
    cd <your-project>
    /tmp/aitools tools fetch      # auto-detects languages, downloads tools from ai-tools release
    /tmp/aitools review           # runs all applicable analyzers, writes report.json + summary.txt

In restricted sandboxes, download via Python `urllib.request`.

## Commands

- `aitools tools list|status|fetch` — manage tools
- `aitools review [path]` — full analysis + aggregated report (`aitools-report.json` and `aitools-summary.txt`)
- `aitools version` — build version
- `aitools exec <cmd> [args]` — run command (sandbox bypass)
- `aitools read|write|find|tree|http` — file/HTTP helpers
- `aitools encrypt|decrypt <file> <key>` — AES-256-GCM

## Tools by language

**Go (21):** staticcheck, gosec, errcheck, govulncheck (reachability), golangci-lint v2 (100+ linters), gofumpt, revive, goimports, bodyclose, unconvert, ineffassign, deadcode, nilaway, gocritic, osv-scanner v2 (remediation), trivy, betterleaks (secrets: detect + validate + revoke), trufflehog, bearer (data-flow security+PII), ruff, nuclei (runtime scanner)

**Rust (5):** cargo-audit, cargo-deny, trivy, osv-scanner, semgrep

**Swift (4):** swiftlint, trivy, osv-scanner, semgrep

**Shell (2):** shellcheck, semgrep

**Python (5):** ruff, semgrep, trivy, osv-scanner, bandit

**JavaScript (4):** semgrep, trivy, osv-scanner, eslint

**C / C++ (2):** cppcheck, semgrep

**Docker (2):** hadolint, trivy

## Best-effort (not auto-installed)

Some tools require language-specific runtimes and are not bundled in the release:

- **semgrep** — `pip install semgrep` (Python runtime)
- **bandit** — `pip install bandit` (Python runtime)
- **eslint** — `npm install -g eslint` (Node runtime)

If these are absent on the system, `review` will skip them gracefully. `tools fetch` attempts to fetch them from the release; if not found there, they are skipped.

## Language detection

Automatic detection by markers:

| Language | Markers |
|---|---|
| Go | `go.mod`, `*.go` |
| Rust | `Cargo.toml`, `*.rs` |
| Swift | `Package.swift`, `*.swift` |
| Shell | `*.sh`, `*.bash` |
| Docker | `Dockerfile`, `docker-compose.yml` |
| Python | `requirements.txt`, `pyproject.toml`, `*.py` |
| JavaScript | `package.json`, `*.js`, `*.ts` |
| C | `*.c`, `*.h`, `Makefile` |
| C++ | `*.cpp`, `*.hpp`, `CMakeLists.txt` |

## Security

Encrypt sensitive reports before transmitting: `aitools encrypt aitools-report.json <key>`. Store keys in secrets/env, not CLI history.

## Build

Push tag `v*` -> GitHub Actions builds aitools + all tools (always latest versions via `go install @latest` + `releases/latest` binary downloads) for linux/amd64.
