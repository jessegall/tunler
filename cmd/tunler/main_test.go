package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"8000":           "127.0.0.1:8000",
		"localhost:3000": "localhost:3000",
		"0.0.0.0:80":     "0.0.0.0:80",
	}
	for in, want := range cases {
		if got := normalizeTarget(in); got != want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsTarget(t *testing.T) {
	for _, s := range []string{"8000", "localhost:3000", "app:80"} {
		if !isTarget(s) {
			t.Errorf("isTarget(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"login", "connect", "status", "my-app"} {
		if isTarget(s) {
			t.Errorf("isTarget(%q) = true, want false", s)
		}
	}
}

func TestRandomDomain(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z]+-[a-z]+-\d{1,2}$`)
	for i := 0; i < 20; i++ {
		d, err := randomDomain()
		if err != nil {
			t.Fatalf("randomDomain: %v", err)
		}
		if !pattern.MatchString(d) {
			t.Fatalf("randomDomain() = %q, not a valid label", d)
		}
	}
}

func TestStripPortHost(t *testing.T) {
	cases := map[string]string{
		"tunler.example.com":      "tunler.example.com",
		"tunler.example.com:8080": "tunler.example.com",
		"localhost:80":            "localhost",
	}
	for in, want := range cases {
		if got := stripPortHost(in); got != want {
			t.Errorf("stripPortHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func isolateHome(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, ".config"))
	t.Setenv("AppData", filepath.Join(tmp, "AppData", "Roaming"))
}

func TestTunnelInfoLifecycle(t *testing.T) {
	isolateHome(t)

	// A registered tunnel with a live PID (our own) is listed.
	info := tunnelInfo{
		Domain: "my-app", Host: "tunler.example.com:443", Target: "127.0.0.1:8000",
		URL: "https://my-app.tunler.example.com", PID: os.Getpid(),
		Mode: "foreground", Started: time.Now(),
	}
	if err := writeInfo(info); err != nil {
		t.Fatalf("writeInfo: %v", err)
	}
	tunnels := readTunnels()
	if len(tunnels) != 1 || tunnels[0].Domain != "my-app" || tunnels[0].Mode != "foreground" {
		t.Fatalf("readTunnels = %+v", tunnels)
	}

	// Dead PIDs are pruned.
	dead := info
	dead.Domain = "dead-app"
	dead.PID = 999999
	writeInfo(dead)
	tunnels = readTunnels()
	if len(tunnels) != 1 {
		t.Fatalf("dead tunnel not pruned: %+v", tunnels)
	}

	// removeInfo forgets the tunnel.
	removeInfo(info.Host, info.Domain)
	if tunnels = readTunnels(); len(tunnels) != 0 {
		t.Fatalf("tunnel not removed: %+v", tunnels)
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("tunler.example.com:443"); got != "tunler.example.com_443" {
		t.Fatalf("sanitize = %q", got)
	}
}
