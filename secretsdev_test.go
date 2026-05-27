package leakferret

import (
	"testing"
)

func TestPlatformTriple(t *testing.T) {
	triple, err := PlatformTriple()
	if err != nil {
		t.Fatalf("PlatformTriple: %v", err)
	}
	if triple == "" {
		t.Fatalf("expected non-empty triple")
	}
}

func TestBuildOptions(t *testing.T) {
	o := build([]Option{WithApply(true), WithBackend(BackendVault), WithExcludes("vendor/")})
	if !o.Apply {
		t.Errorf("expected Apply true")
	}
	if o.Backend != BackendVault {
		t.Errorf("expected vault backend, got %q", o.Backend)
	}
	if len(o.Excludes) != 1 || o.Excludes[0] != "vendor/" {
		t.Errorf("excludes: %v", o.Excludes)
	}
}
