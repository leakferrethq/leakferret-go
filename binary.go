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
	"aarch64-apple-darwin":     "4db78de31252e8a2964528c817f12c73d46b660f453398c9c2f0feba6b370772",
	"aarch64-pc-windows-msvc":  "021dce80072ae4cd553a23b05cddc9a878226668c92570df1b80c3221e034493",
	"x86_64-apple-darwin":      "b37747b336a3a18875b05a5c6e9aa736f53518fbcf8e722993f434cea41e0aa2",
	"x86_64-pc-windows-msvc":   "b0e32599f9d04e391d4b2d703e648c0a64739b15317434b0625eb00686cc6bb1",
	"x86_64-unknown-linux-gnu": "05420ee2cd7e1d617f96caf098fda4a260ba361bc70af7e47da004959986cbbd",
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
