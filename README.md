# leakferret (Go module wrapper)

Go module wrapper around the native [`leakferret`](https://github.com/leakferrethq/leakferret)
binary. Downloads the right platform binary on first use and caches
it under `$XDG_CACHE_HOME/leakferret/`.

## Install

```bash
go get github.com/leakferrethq/leakferret-go
```

CLI:

```bash
go install github.com/leakferrethq/leakferret-go/cmd/leakferret@latest
leakferret scan .
```

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
    findings, err := leakferret.Verify(ctx, ".", leakferret.WithVerifyMode(leakferret.VerifyModeOnlyVerified))
    if err != nil {
        log.Fatal(err)
    }
    for _, f := range findings {
        fmt.Printf("%s:%d %s [%s] %s\n", f.Path, f.Line, f.Pattern, f.Verdict, f.MatchRedacted)
    }
}
```

## Configuration

* `LEAKFERRET_BIN` — absolute path to a pre-positioned binary. Skips
  the download/cache step.
* Standard cache paths: `$XDG_CACHE_HOME/leakferret/`,
  `$LOCALAPPDATA/leakferret/cache/` (Windows),
  `~/Library/Caches/leakferret/` (macOS),
  `~/.cache/leakferret/` (Linux fallback).

## License

MIT.
