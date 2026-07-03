package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jessegall/tunler/internal/server"
)

// noEnv is a getenv that always returns empty.
func noEnv(string) string { return "" }

func TestLoadConfigPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"domain": "file.example.com", "email": "file@x.nl"}`), 0o600)

	env := map[string]string{"TUNLER_DOMAIN": "env.example.com", "TUNLER_PASSWORD": "envpw"}
	getenv := func(k string) string { return env[k] }

	// flag > env > file: --domain wins over env and file.
	cfg, _, err := loadConfig([]string{"--config", path, "--domain", "flag.example.com"}, getenv)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Domain != "flag.example.com" {
		t.Errorf("domain = %q, want flag.example.com", cfg.Domain)
	}
	// email came only from the file (no env/flag), so it survives.
	if cfg.Email != "file@x.nl" {
		t.Errorf("email = %q, want file@x.nl", cfg.Email)
	}
	// password from env is hashed.
	if cfg.PasswordHash != server.HashPassword("envpw") {
		t.Error("env password not hashed into PasswordHash")
	}
}

func TestLoadConfigEnvOverFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"domain": "file.example.com"}`), 0o600)

	env := map[string]string{"TUNLER_DOMAIN": "env.example.com"}
	cfg, _, err := loadConfig([]string{"--config", path}, func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Domain != "env.example.com" {
		t.Errorf("domain = %q, want env.example.com (env over file)", cfg.Domain)
	}
}

func TestLoadConfigDefaultsBinDir(t *testing.T) {
	cfg, _, err := loadConfig([]string{"--domain", "x.example.com", "--data", "/tmp/tdata"}, noEnv)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.BinDir != filepath.Join("/tmp/tdata", "bin") {
		t.Errorf("BinDir = %q, want <data>/bin", cfg.BinDir)
	}
}
