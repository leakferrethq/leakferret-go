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
		if cpu == "aarch64" {
			return "", fmt.Errorf("aarch64-linux has no prebuilt binary yet; build from source")
		}
		return cpu + "-unknown-linux-gnu", nil
	case "darwin":
		return cpu + "-apple-darwin", nil
	case "windows":
		return cpu + "-pc-windows-msvc", nil
	default:
		return "", fmt.Errorf("unsupported GOOS: %s", runtime.GOOS)
	}
}
