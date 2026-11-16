# AI Tools

Single binary `aitools` + 11 Go analysis tools for sandboxed AI environments (or any linux/amd64 machine).

## What is inside

- **aitools** — sandbox-bypass helper: `exec`, `read`, `write`, `find`, `tree`, `http`, plus AES-256-GCM `encrypt` / `decrypt`
- **Analysis tools** (linux/amd64, UPX-compressed, attached to each release):
  staticcheck, gosec, errcheck, govulncheck, golangci-lint, goimports, revive, deadcode, ineffassign, unconvert, bodyclose

## Quick start

```bash
# main binary from the latest release
curl -L -o /tmp/aitools https://github.com/PavelNeyman/ai-tools/releases/latest/download/aitools-linux-amd64
chmod +x /tmp/aitools

# download all analysis tools from the latest release
/tmp/aitools tools fetch

# check
/tmp/aitools tools status

# full analysis of a repo + aggregated report
/tmp/aitools review https://github.com/PavelNeyman/netductor
```

In restricted sandboxes where curl is blocked, download via Python `urllib.request` — see [docs/USAGE.md](docs/USAGE.md).

## Usage

Full command reference and analysis workflow: **[docs/USAGE.md](docs/USAGE.md)**

## Build

Push a tag `v*` — GitHub Actions builds `aitools` and all tools for linux/amd64 and attaches them to the release.
