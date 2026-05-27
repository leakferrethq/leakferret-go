// Command leakferret is a thin pass-through to the native binary
// (`go install` puts this in $GOBIN, then exec's the cached binary).
//
//   $ go install github.com/leakferrethq/leakferret-go/cmd/leakferret@latest
//   $ leakferret scan .
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	leakferret "github.com/leakferrethq/leakferret-go"
)

func main() {
	bin, err := leakferret.BinaryPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakferret: %v\n", err)
		os.Exit(2)
	}
	cmd := exec.Command(bin, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(ws.ExitStatus())
			}
		}
		fmt.Fprintf(os.Stderr, "leakferret: %v\n", err)
		os.Exit(2)
	}
}
