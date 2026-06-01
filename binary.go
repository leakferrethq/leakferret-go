package leakferret

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// checksums pins the SHA256 of each release tarball to Version. The download is
// verified against these before extraction, so a tampered or corrupted release
// asset is rejected rather than executed. Because the digests live in the
// module source, auditing a tagged version tells you exactly which binary bytes
// it will run. Regenerate on every binary bump from the *.tar.gz.sha256 files.
var checksums = map[string]string{
	"aarch64-apple-darwin":     "62d7152954e3e2e50d8423c8a1e792ba1783123b8a9d8c5fbc2a71013e890992",
	"aarch64-pc-windows-msvc":  "6ad3eb20a661579c11857259159f8fb55b26f72608c75ecc206fff5f9da9c800",
	"x86_64-apple-darwin":      "d8b28edf427b975412458007069a848e16cea45825e43dff3652bdcd3fd3f1d3",
	"x86_64-pc-windows-msvc":   "f447424f148a6874dc2ead208eb460a9f6b20d6ddbce6f74ca9b2d47655e1b2b",
	"x86_64-unknown-linux-gnu": "bf24746f1188d14b2b420e760ebd374a4f88a68ea1b718e7977d8c7309a9f1da",
}

// BinaryPath returns the absolute path to the leakferret binary,
// downloading + caching it on first call.
//
// Override via the LEAKFERRET_BIN env var (useful for air-gapped CI
// or local dev against a freshly-built binary).
func BinaryPath() (string, error) {
	if env := os.Getenv("LEAKFERRET_BIN"); env != "" {
		if _, err := os.Stat(env); err != nil {
			return "", fmt.Errorf("LEAKFERRET_BIN set but file not found: %w", err)
		}
		return env, nil
	}
	return ensureCached()
}

var (
	cacheOnce sync.Once
	cachedPath string
	cacheErr   error
)

func ensureCached() (string, error) {
	cacheOnce.Do(func() {
		dir, err := cacheDir()
		if err != nil {
			cacheErr = err
			return
		}
		triple, err := PlatformTriple()
		if err != nil {
			cacheErr = err
			return
		}
		dest := filepath.Join(dir, "v"+Version, binaryName())
		if _, err := os.Stat(dest); err == nil {
			cachedPath = dest
			return
		}
		if err := download(triple, dest); err != nil {
			cacheErr = err
			return
		}
		cachedPath = dest
	})
	return cachedPath, cacheErr
}

func cacheDir() (string, error) {
	if v := os.Getenv("XDG_CACHE_HOME"); v != "" {
		return filepath.Join(v, "leakferret"), nil
	}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, "leakferret", "cache"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Caches", "leakferret"), nil
	}
	return filepath.Join(home, ".cache", "leakferret"), nil
}

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "leakferret.exe"
	}
	return "leakferret"
}

// download fetches the platform archive from GitHub Releases and
// extracts the binary to dest.
func download(triple, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	expected, ok := checksums[triple]
	if !ok {
		return fmt.Errorf(
			"no pinned checksum for platform %s; refusing to run an unverified binary "+
				"(build from source and set LEAKFERRET_BIN)", triple)
	}
	url := fmt.Sprintf(
		"https://github.com/leakferrethq/leakferret/releases/download/v%s/leakferret-%s-%s.tar.gz",
		Version, Version, triple,
	)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	// Read the whole tarball, verify its SHA256 against the pinned value, and
	// only then unpack. Nothing is written to the cache (let alone marked
	// executable) until the bytes match, so a tampered or truncated release
	// asset is rejected rather than run.
	archive, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read archive: %w", err)
	}
	sum := sha256.Sum256(archive)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf(
			"checksum mismatch for %s:\n  expected %s\n  got      %s\n"+
				"refusing to install a binary that does not match the pinned hash",
			url, expected, actual)
	}

	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		if filepath.Base(hdr.Name) != binaryName() {
			continue
		}
		out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("open dest: %w", err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			_ = out.Close()
			return fmt.Errorf("write binary: %w", err)
		}
		if err := out.Close(); err != nil {
			return fmt.Errorf("close binary: %w", err)
		}
		return nil
	}
	return fmt.Errorf("binary %s not found in archive", binaryName())
}
