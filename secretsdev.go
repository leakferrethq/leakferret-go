// Package leakferret is a Go wrapper around the native leakferret
// binary written in Rust. The wrapper downloads the right binary for
// the host platform on first use and caches it under
// $XDG_CACHE_HOME/leakferret/ (or platform equivalent).
//
// The package mirrors the binary's CLI shape: Scan, Verify, Rewrite,
// each returning a slice of Findings parsed from the binary's JSON
// output.
//
// Example:
//
//	findings, err := leakferret.Scan(ctx, ".")
//	if err != nil { log.Fatal(err) }
//	for _, f := range findings {
//	    fmt.Printf("%s:%d %s [%s]\n", f.Path, f.Line, f.Pattern, f.Verdict)
//	}
package leakferret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
)

// Version is the binary version this wrapper targets. Update in lockstep
// with the Rust crate version.
const Version = "0.1.3"

// VerifyMode controls live-credential verification.
type VerifyMode string

const (
	VerifyModeNone         VerifyMode = "none"
	VerifyModeBestEffort   VerifyMode = "best-effort"
	VerifyModeOnlyVerified VerifyMode = "only-verified"
	VerifyModeEverVerified VerifyMode = "ever-verified"
)

// RewriteBackend controls which secret-manager the rewriter
// emits seed commands for.
type RewriteBackend string

const (
	BackendEnv               RewriteBackend = "env"
	BackendVault             RewriteBackend = "vault"
	BackendDoppler           RewriteBackend = "doppler"
	BackendAWSSecretsManager RewriteBackend = "aws-secrets-manager"
	BackendInfisical         RewriteBackend = "infisical"
)

// Options shared by Scan / Verify / Rewrite.
type Options struct {
	Excludes      []string
	Only          []string
	ShowFixtures  bool
	VerifyMode    VerifyMode
	Backend       RewriteBackend
	Apply         bool
	BinaryPath    string // override; default: managed cache
	VerifierTimeoutSecs int
}

// Finding is one detected secret candidate. Mirrors FindingView from
// the Rust core (raw match stripped on serialise).
type Finding struct {
	Path           string             `json:"path"`
	Line           int                `json:"line"`
	Column         int                `json:"column"`
	Pattern        string             `json:"pattern"`
	Severity       string             `json:"severity"`
	MatchRedacted  string             `json:"match_redacted"`
	Verdict        string             `json:"verdict"`
	Reason         *string            `json:"reason,omitempty"`
	Confidence     *float32           `json:"confidence,omitempty"`
	Fingerprint    *string            `json:"fingerprint,omitempty"`
	Verification   *VerificationOutcome `json:"verification,omitempty"`
}

// VerificationOutcome reflects the provider verifier result.
type VerificationOutcome struct {
	Status     string          `json:"status"`            // "verified" | "invalid" | "unverified"
	Provider   string          `json:"provider"`
	HTTPStatus *int            `json:"http_status,omitempty"`
	Reason     *string         `json:"reason,omitempty"`
	Meta       json.RawMessage `json:"meta,omitempty"`
}

// Scan runs the regex pre-filter and returns candidate findings. Verdicts
// are 'unknown' — call Verify for classification + provider verification.
func Scan(ctx context.Context, path string, opts ...Option) ([]Finding, error) {
	o := build(opts)
	args := []string{"scan", path, "--format", "json"}
	args = append(args, flagPairs(o)...)
	return invoke(ctx, o.BinaryPath, args)
}

// Verify runs scan + offline classifier + (optionally) provider verifiers.
func Verify(ctx context.Context, path string, opts ...Option) ([]Finding, error) {
	o := build(opts)
	mode := o.VerifyMode
	if mode == "" {
		mode = VerifyModeBestEffort
	}
	timeout := o.VerifierTimeoutSecs
	if timeout == 0 {
		timeout = 10
	}
	args := []string{
		"verify", path, "--format", "json",
		"--verify-mode", string(mode),
		"--verifier-timeout-secs", fmt.Sprintf("%d", timeout),
	}
	args = append(args, flagPairs(o)...)
	return invoke(ctx, o.BinaryPath, args)
}

// Rewrite runs scan + classify + propose-rewrite. Set WithApply(true)
// to write the rewrites in place.
func Rewrite(ctx context.Context, path string, opts ...Option) ([]Finding, error) {
	o := build(opts)
	backend := o.Backend
	if backend == "" {
		backend = BackendEnv
	}
	args := []string{
		"rewrite", path, "--format", "json",
		"--backend", string(backend),
	}
	if o.Apply {
		args = append(args, "--apply")
	}
	args = append(args, flagPairs(o)...)
	return invoke(ctx, o.BinaryPath, args)
}

// Option configures one of the Scan/Verify/Rewrite calls. Use the
// helpers below; we avoid exposing Options directly so the API is
// future-proof.
type Option func(*Options)

func WithExcludes(globs ...string) Option { return func(o *Options) { o.Excludes = append(o.Excludes, globs...) } }
func WithOnly(paths ...string) Option     { return func(o *Options) { o.Only = append(o.Only, paths...) } }
func WithShowFixtures(b bool) Option      { return func(o *Options) { o.ShowFixtures = b } }
func WithVerifyMode(m VerifyMode) Option  { return func(o *Options) { o.VerifyMode = m } }
func WithBackend(b RewriteBackend) Option { return func(o *Options) { o.Backend = b } }
func WithApply(b bool) Option             { return func(o *Options) { o.Apply = b } }
func WithBinary(path string) Option       { return func(o *Options) { o.BinaryPath = path } }
func WithVerifierTimeout(secs int) Option { return func(o *Options) { o.VerifierTimeoutSecs = secs } }

func build(opts []Option) Options {
	o := Options{}
	for _, f := range opts {
		f(&o)
	}
	return o
}

func flagPairs(o Options) []string {
	var args []string
	for _, g := range o.Excludes {
		args = append(args, "--exclude", g)
	}
	for _, p := range o.Only {
		args = append(args, "--only", p)
	}
	if o.ShowFixtures {
		args = append(args, "--show-fixtures")
	}
	return args
}

func invoke(ctx context.Context, binOverride string, args []string) ([]Finding, error) {
	bin := binOverride
	if bin == "" {
		var err error
		bin, err = BinaryPath()
		if err != nil {
			return nil, err
		}
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Exit 1 is "findings present" — not an error.
			if exitErr.ExitCode() == 1 {
				return parseFindings(out)
			}
			return nil, fmt.Errorf("leakferret: %w: %s", err, string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("leakferret: %w", err)
	}
	return parseFindings(out)
}

func parseFindings(out []byte) ([]Finding, error) {
	if len(out) == 0 {
		return nil, nil
	}
	var findings []Finding
	if err := json.Unmarshal(out, &findings); err != nil {
		return nil, fmt.Errorf("parse findings JSON: %w", err)
	}
	return findings, nil
}
