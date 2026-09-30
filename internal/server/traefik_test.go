package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncTraefik(t *testing.T) {
	s := newTestState(t)
	s.Claim("my-app", "me@x.nl")
	s.Claim("api", "me@x.nl")

	cfg := DefaultConfig()
	cfg.Domain = "tunler.example.com"
	cfg.PasswordHash = mustHash(t, "pw")
	cfg.TraefikFile = filepath.Join(t.TempDir(), "tunler.yml")
	srv := New(cfg, s)

	if err := srv.SyncTraefik(); err != nil {
		t.Fatalf("SyncTraefik: %v", err)
	}
	raw, err := os.ReadFile(cfg.TraefikFile)
	if err != nil {
		t.Fatalf("read generated file: %v", err)
	}
	got := string(raw)

	wantRule := "rule: HostSNI(`tunler.example.com`) || HostSNI(`api.tunler.example.com`) || HostSNI(`my-app.tunler.example.com`)"
	for _, want := range []string{wantRule, "passthrough: true", `address: "tunler:443"`} {
		if !strings.Contains(got, want) {
			t.Errorf("generated config missing %q:\n%s", want, got)
		}
	}
}

func TestSyncTraefikDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domain = "x.com"
	srv := New(cfg, newTestState(t))
	if err := srv.SyncTraefik(); err != nil { // no TraefikFile set: no-op
		t.Fatalf("SyncTraefik without file: %v", err)
	}
}
