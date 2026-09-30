package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jessegall/tunler/internal/client"
)

// tunnelInfo is the pidfile written for every running tunnel
// (~/.config/tunler/run/<domain>@<host>.json). Foreground tunnels register
// too, so `tunler list` shows everything running on this machine.
type tunnelInfo struct {
	Domain  string    `json:"domain"`
	Host    string    `json:"host"`
	Target  string    `json:"target"`
	URL     string    `json:"url"`
	PID     int       `json:"pid"`
	Mode    string    `json:"mode"`            // "foreground" or "background"
	Ready   bool      `json:"ready,omitempty"` // set once the tunnel is up
	Log     string    `json:"log,omitempty"`
	Started time.Time `json:"started"`
}

// writeInfo records a running tunnel; removeInfo forgets it.
func writeInfo(info tunnelInfo) error {
	path, err := infoPath(info.Host, info.Domain)
	if err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(info, "", "  ")
	return os.WriteFile(path, raw, 0o600)
}

func removeInfo(host, domain string) {
	if path, err := infoPath(host, domain); err == nil {
		os.Remove(path)
		os.Remove(path + ".lock")
	}
}

// holdTunnelLock takes an exclusive lock next to the tunnel's pidfile for as
// long as the tunnel runs. A held lock proves the pidfile's process is this
// tunnel, not an unrelated process that reused the PID after a crash. The
// returned func releases it.
func holdTunnelLock(host, domain string) func() {
	path, err := infoPath(host, domain)
	if err != nil {
		return func() {}
	}
	return lockFile(path + ".lock")
}

// running reports whether the tunnel of the pidfile at path is still up. It
// trusts the tunnel's lock when there is one and falls back to the PID for
// pidfiles written without it.
func running(info tunnelInfo, path string) bool {
	if held, known := lockHeld(path + ".lock"); known {
		return held
	}
	return alive(info.PID)
}

// readInfo loads a single pidfile.
func readInfo(path string) (tunnelInfo, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return tunnelInfo{}, false
	}
	var info tunnelInfo
	if json.Unmarshal(raw, &info) != nil {
		return tunnelInfo{}, false
	}
	return info, true
}

func tunlerDir(sub string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "tunler", sub)
	return dir, os.MkdirAll(dir, 0o700)
}

// sanitize makes a host safe for use in a file name.
func sanitize(s string) string {
	return strings.NewReplacer(":", "_", "/", "_").Replace(s)
}

func infoPath(host, domain string) (string, error) {
	dir, err := tunlerDir("run")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, domain+"@"+sanitize(host)+".json"), nil
}

// spawnDetached re-executes tunler connect in the background and waits for the
// child to mark its pidfile ready (or die). The child owns its pidfile, and
// its secret is passed via the environment so it never appears in argv.
func spawnDetached(o opts, cfg client.Config, _ client.Store) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find own executable: %w", err)
	}
	logDir, err := tunlerDir("logs")
	if err != nil {
		return fmt.Errorf("cannot create log dir: %w", err)
	}
	logPath := filepath.Join(logDir, cfg.Domain+"@"+sanitize(cfg.Host)+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("cannot create log file: %w", err)
	}
	defer logFile.Close()

	args := []string{"connect", cfg.Target,
		"--host=" + cfg.Host, "--domain=" + cfg.Domain,
		"--log-file=" + logPath, "--inspect=0"}
	if o.insecure {
		args = append(args, "--insecure")
	}
	if o.ephemeral {
		args = append(args, "--ephemeral")
	}

	cmd := exec.Command(exe, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = detachAttr()
	// Secrets go through the environment, not argv (argv is world-readable).
	cmd.Env = append(os.Environ(), "TUNLER_SECRET="+cfg.Secret)
	if o.auth != "" {
		cmd.Env = append(cmd.Env, "TUNLER_AUTH="+o.auth)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start background tunnel: %w", err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	path, _ := infoPath(cfg.Host, cfg.Domain)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if info, ok := readInfo(path); ok && info.Ready && info.PID == pid {
			fmt.Printf("%s -> %s  (background, pid %d)\n", cfg.URL(), cfg.Target, pid)
			fmt.Fprintf(os.Stderr, "logs: %s\ndisconnect with: tunler disconnect %s\n", logPath, cfg.Domain)
			return nil
		}
		if !alive(pid) {
			raw, _ := os.ReadFile(logPath)
			return fmt.Errorf("background tunnel failed to start:\n%s", strings.TrimSpace(string(raw)))
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for tunnel to come up; check logs: %s", logPath)
}

// readTunnels loads all pidfiles, pruning entries whose process is gone.
func readTunnels() []tunnelInfo {
	dir, err := tunlerDir("run")
	if err != nil {
		return nil
	}
	entries, _ := os.ReadDir(dir)
	var out []tunnelInfo
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		info, ok := readInfo(path)
		if !ok || !running(info, path) {
			os.Remove(path) // corrupt or stale
			os.Remove(path + ".lock")
			continue
		}
		out = append(out, info)
	}
	return out
}

func cmdList(args []string) error {
	o, _, err := parse("list", args)
	if err != nil {
		return err
	}
	tunnels := readTunnels()
	if o.jsonOut {
		if tunnels == nil {
			tunnels = []tunnelInfo{}
		}
		json.NewEncoder(os.Stdout).Encode(tunnels)
		return nil
	}
	if len(tunnels) == 0 {
		fmt.Fprintln(os.Stderr, "no tunnels running (start one with: tunler <port> --domain=<name>)")
		return nil
	}
	for _, t := range tunnels {
		fmt.Printf("%-40s -> %-21s  %-10s  pid %-7d up %s\n",
			t.URL, t.Target, t.Mode, t.PID, time.Since(t.Started).Round(time.Second))
	}
	return nil
}

func cmdDisconnect(args []string) error {
	o, positional, err := parse("disconnect", args)
	if err != nil {
		return err
	}
	if o.domain == "" && len(positional) == 1 {
		o.domain = positional[0]
	}

	tunnels := readTunnels()
	if len(tunnels) == 0 {
		return fmt.Errorf("no tunnels running")
	}

	var targets []tunnelInfo
	switch {
	case o.all:
		targets = tunnels
	case o.domain != "":
		for _, t := range tunnels {
			if t.Domain == o.domain && (o.host == "" || t.Host == o.host) {
				targets = append(targets, t)
			}
		}
		if len(targets) == 0 {
			return fmt.Errorf("no tunnel for domain %q", o.domain)
		}
	case len(tunnels) == 1:
		targets = tunnels // only one running: no need to name it
	default:
		return usageErr("multiple tunnels running; pass a domain (tunler disconnect <domain>) or --all")
	}

	for _, t := range targets {
		proc, err := os.FindProcess(t.PID)
		if err == nil {
			err = terminate(proc)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not stop %s (pid %d): %v\n", t.Domain, t.PID, err)
			continue
		}
		removeInfo(t.Host, t.Domain)
		fmt.Fprintf(os.Stderr, "disconnected %s (pid %d)\n", t.URL, t.PID)
	}
	return nil
}

func cmdLogs(args []string) error {
	o, positional, err := parse("logs", args)
	if err != nil {
		return err
	}
	if o.domain == "" && len(positional) == 1 {
		o.domain = positional[0]
	}
	tunnels := readTunnels()
	var found *tunnelInfo
	switch {
	case o.domain != "":
		for i := range tunnels {
			if tunnels[i].Domain == o.domain {
				found = &tunnels[i]
				break
			}
		}
	case len(tunnels) == 1:
		found = &tunnels[0]
	}
	if found == nil {
		return usageErr("no running tunnel found (tunler logs <domain>)")
	}
	if found.Log == "" {
		return fmt.Errorf("%s is a foreground tunnel; its output is in the terminal running it", found.Domain)
	}
	f, err := os.Open(found.Log)
	if err != nil {
		return err
	}
	defer f.Close()
	io.Copy(os.Stdout, f)
	for o.follow {
		time.Sleep(500 * time.Millisecond)
		io.Copy(os.Stdout, f) // picks up whatever was appended since
	}
	return nil
}
