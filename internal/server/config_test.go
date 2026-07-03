package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Limits.MaxConnsPerTunnel != 64 {
		t.Errorf("MaxConnsPerTunnel = %d, want 64", c.Limits.MaxConnsPerTunnel)
	}
	if time.Duration(c.Limits.DataConnIdleTimeout) != 5*time.Minute {
		t.Errorf("DataConnIdleTimeout = %s, want 5m", c.Limits.DataConnIdleTimeout)
	}
	if !c.Lockout.Enabled || c.Lockout.Threshold != 5 {
		t.Errorf("lockout = %+v", c.Lockout)
	}
	if c.Registration.Mode != "open" {
		t.Errorf("registration mode = %q, want open", c.Registration.Mode)
	}
}

func TestLoadConfigOverlay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{
		"domain": "tunler.example.com",
		"downloads": {"require_auth": true},
		"limits": {"max_conns_per_tunnel": 8, "response_header_timeout": "12s"},
		"lockout": {"enabled": false},
		"registration": {"mode": "allowlist", "allowlist": ["a@x.nl"]}
	}`), 0o600)

	c, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.Domain != "tunler.example.com" {
		t.Errorf("domain = %q", c.Domain)
	}
	if !c.Downloads.RequireAuth {
		t.Error("require_auth not applied")
	}
	if c.Limits.MaxConnsPerTunnel != 8 {
		t.Errorf("max_conns = %d, want 8 (from file)", c.Limits.MaxConnsPerTunnel)
	}
	if time.Duration(c.Limits.ResponseHeaderTimeout) != 12*time.Second {
		t.Errorf("response_header_timeout = %s, want 12s", c.Limits.ResponseHeaderTimeout)
	}
	// A field omitted from the file keeps its default.
	if time.Duration(c.Limits.DataConnIdleTimeout) != 5*time.Minute {
		t.Errorf("idle timeout = %s, want default 5m", c.Limits.DataConnIdleTimeout)
	}
	if c.Lockout.Enabled {
		t.Error("lockout should be disabled by file")
	}
	if len(c.Reserved) == 0 {
		t.Error("reserved defaults lost")
	}
}

func TestLoadConfigMissingPath(t *testing.T) {
	c, err := LoadConfig("")
	if err != nil {
		t.Fatalf("empty path: %v", err)
	}
	if c.Limits.MaxConnsPerTunnel != DefaultConfig().Limits.MaxConnsPerTunnel {
		t.Error("empty path should return defaults")
	}
}

func TestHashPassword(t *testing.T) {
	if h := HashPassword("hunter2"); len(h) != 64 {
		t.Fatalf("hash length = %d, want 64", len(h))
	}
	if HashPassword("a") == HashPassword("b") {
		t.Fatal("distinct passwords hash equal")
	}
}

func TestRegistrationAllowsEmail(t *testing.T) {
	open := Registration{Mode: "open"}
	if !open.allowsEmail("anyone@x.nl") {
		t.Error("open mode should allow any email")
	}
	list := Registration{Mode: "allowlist", Allowlist: []string{"ok@x.nl"}}
	if !list.allowsEmail("ok@x.nl") {
		t.Error("allowlisted email rejected")
	}
	if list.allowsEmail("nope@x.nl") {
		t.Error("non-allowlisted email accepted")
	}
}
