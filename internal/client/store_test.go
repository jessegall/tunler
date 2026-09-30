package client

import (
	"os"
	"path/filepath"
	"testing"
)

// isolateConfig points os.UserConfigDir at a temp dir for the test.
func isolateConfig(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)                                         // darwin
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, ".config"))    // linux
	t.Setenv("AppData", filepath.Join(tmp, "AppData", "Roaming")) // windows
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("no user config dir in this environment: %v", err)
	}
	return dir
}

func TestStoreRoundtrip(t *testing.T) {
	isolateConfig(t)

	if s := LoadStore(); len(s.Hosts) != 0 || s.DefaultHost != "" {
		t.Fatalf("fresh store not empty: %+v", s)
	}

	s := LoadStore()
	s.DefaultHost = "tunler.example.com"
	s.Hosts["tunler.example.com"] = HostCreds{User: "me", Secret: "s3cret"}
	s.Hosts["old.example.com"] = HostCreds{Email: "me@x.nl", Secret: "old"} // saved by an older client
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got := LoadStore()
	if got.DefaultHost != "tunler.example.com" {
		t.Errorf("DefaultHost = %q", got.DefaultHost)
	}
	if creds := got.Hosts["tunler.example.com"]; creds.User != "me" || creds.Secret != "s3cret" {
		t.Errorf("creds = %+v", creds)
	}
	if creds := got.Hosts["old.example.com"]; creds.User != "me@x.nl" {
		t.Errorf("old email login not read as the username: %+v", creds)
	}
}

func TestInstalledHost(t *testing.T) {
	dir := isolateConfig(t)

	if got := InstalledHost(); got != "" {
		t.Fatalf("InstalledHost with no file = %q, want empty", got)
	}

	path := filepath.Join(dir, "tunler", "server")
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("tunler.example.com\n"), 0o600)

	if got := InstalledHost(); got != "tunler.example.com" {
		t.Fatalf("InstalledHost = %q", got)
	}
}
