# AI Tools

Universal code review and security analysis toolkit for **Go, Rust, Swift, Shell, Python, JavaScript, C, C++, Docker**.

Single binary `aitools` + 25+ bundled analyzers (staticcheck, gosec, golangci-lint v2, trivy, osv-scanner v2, betterleaks, trufflehog, bearer, ruff, nuclei, swiftlint, shellcheck, hadolint, cppcheck, cargo-audit, cargo-deny, semgrep-ready and more).

## Quick start

    curl -L -o /tmp/aitools https://github.com/PavelNeyman/ai-tools/releases/latest/download/aitools-linux-amd64
    chmod +x /tmp/aitools
    cd <your-project>
    /tmp/aitools tools fetch      # auto-detects languages, downloads tools
    /tmp/aitools review           # full analysis + report.json + summary.txt

In restricted sandboxes, download via Python `urllib.request` (GET the release asset URL).

## Documentation

Full command reference: **[docs/USAGE.md](docs/USAGE.md)**

## Build

Push tag `v*` -> GitHub Actions builds everything (always latest versions via `go install @latest` + binary `releases/latest` downloads) for linux/amd64.


## Security notes

- `encrypt`/`decrypt` use AES-256-GCM (passphrase via arg or `AITOOLS_KEY`).
- `tools sync` refuses plaintext; requires `AITOOLS_ALLOW_UPLOAD=1`.
- MCP `exec` requires `AITOOLS_MCP_ALLOW_EXEC=1`.
