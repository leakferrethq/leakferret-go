package leakferret

import (
	"fmt"
	"runtime"
)

// PlatformTriple returns the Rust-style target triple for the host.
func PlatformTriple() (string, error) {
	var cpu string
	switch runtime.GOARCH {
	case "amd64":
		cpu = "x86_64"
	case "arm64":
		cpu = "aarch64"
	default:
		return "", fmt.Errorf("unsupported GOARCH: %s", runtime.GOARCH)
	}

	switch runtime.GOOS {
	case "linux":
		return cpu + "-unknown-linux-gnu", nil
	case "darwin":
		return cpu + "-apple-darwin", nil
	case "windows":
		return cpu + "-pc-windows-gnu", nil
	default:
		return "", fmt.Errorf("unsupported GOOS: %s", runtime.GOOS)
	}
}
