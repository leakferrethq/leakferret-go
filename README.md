# leakferret (Go module)

> MCP-native secret scanner — verified findings, agent-applied rewrites.

Go module wrapper around the native [`leakferret`](https://github.com/leakferrethq/leakferret)
binary. This module ships no scanning logic of its own: it downloads the
prebuilt, statically-linked binary (written in Rust) from GitHub Releases on
first use, caches it locally, and shells out to it. All the work — scan,
classify, verify, rewrite — happens in that single binary.

## What leakferret does

leakferret finds hardcoded secrets and API keys in your code and helps you
remove them, in five stations:

1. **Scan** — regex pre-filter over files; respects `.gitignore` and also reads
   dotfiles like `.env`.
2. **Catalog** — a signed database of known-public example credentials (Stripe
   test keys, `AKIAIOSFODNN7EXAMPLE`, jwt.io samples) so documented examples are
   marked `FIXTURE` instead of false-alarming.
3. **Classify** — a `REAL` / `FIXTURE` / `UNKNOWN` verdict, from offline
   heuristics or by asking the host editor/agent language model (no extra API
   key, no cost).
4. **Verify** — a real but harmless API call to the provider (AWS SigV4,
   GitHub, GitLab, Stripe, OpenAI, Anthropic, Slack, Twilio, SendGrid, Mailgun,
   Datadog, Heroku, npm, PyPI, DigitalOcean) to confirm a key is live, plus a
   trufflehog fallback.
5. **Rewrite** — swap a hardcoded literal for an environment-variable lookup,
   add a `.env.example` line, and print secret-manager seed commands.

**Privacy invariant:** the full secret value never leaves your machine. Only a
redacted first-4-plus-last-4 preview (e.g. `AKIA...4XYZ`) is ever written to a
report, log, network message, or model prompt. Verification calls go straight
from your machine to the provider — leakferret has no servers.

## Install

As a CLI:

```bash
go install github.com/leakferrethq/leakferret-go/cmd/leakferret@latest
leakferret scan .
```

As a library:

```bash
go get github.com/leakferrethq/leakferret-go
```

Requires Go 1.22+.

## CLI

The installed `leakferret` command exposes the full upstream interface:

```bash
leakferret scan .
leakferret verify . --only-verified
leakferret rewrite . --apply --backend doppler
leakferret baseline init
leakferret catalog info
leakferret mcp                 # MCP server on stdio
```

`leakferret scan --git` walks commit history. Output formats are `pretty`,
`json`, and `sarif` (for GitHub Code Scanning).

## Library use

```go
package main

import (
    "context"
    "fmt"
    "log"

    leakferret "github.com/leakferrethq/leakferret-go"
)

func main() {
    ctx := context.Background()
    findings, err := leakferret.Verify(ctx, ".",
        leakferret.WithVerifyMode(leakferret.VerifyModeOnlyVerified))
    if err != nil {
        log.Fatal(err)
    }
    for _, f := range findings {
        fmt.Printf("%s:%d %s [%s] %s\n",
            f.Path, f.Line, f.Pattern, f.Verdict, f.MatchRedacted)
    }
}
```

The first call resolves the host target triple, downloads the matching binary
from GitHub Releases, and caches it. Subsequent calls reuse the cache.

## Configuration

- **`LEAKFERRET_BIN`** — absolute path to a pre-positioned binary. Set this and
  the module runs it directly, skipping the download and cache entirely. Every
  leakferret wrapper honors this variable; it is the recommended path for
  air-gapped or offline environments.

  ```bash
  export LEAKFERRET_BIN=/opt/leakferret/leakferret
  ```

- **Cache locations** (used when `LEAKFERRET_BIN` is unset):
  - `$XDG_CACHE_HOME/leakferret/`
  - `$LOCALAPPDATA/leakferret/cache/` (Windows)
  - `~/Library/Caches/leakferret/` (macOS)
  - `~/.cache/leakferret/` (Linux fallback)

## Platforms

Prebuilt binaries are published for `x86_64-unknown-linux-gnu`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, and
`aarch64-pc-windows-msvc`. Linux ARM64 (`aarch64-unknown-linux-gnu`) is not yet
published; on that platform, build the engine from source and point
`LEAKFERRET_BIN` at it.

## License

MIT for this module and the bundled binary. The fixture catalog **data** is
CC-BY-SA-4.0 — see [`leakferret-catalog`](https://github.com/leakferrethq/leakferret-catalog).

---

Part of [leakferret](https://github.com/leakferrethq/leakferret) ·
[leakferret.com](https://leakferret.com) ·
maintained by Maria Khan &lt;missusk@protonmail.com&gt;.
