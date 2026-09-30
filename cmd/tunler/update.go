package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jessegall/tunler/internal/client"
)

// cmdUpdate replaces the running binary with the one distributed by the tunler
// server over TLS (the same files `curl <host>/install | sh` uses). The
// server's .sha256 file doubles as the version check: if the published
// checksum matches the running binary, there is nothing to do. --insecure is
// refused here: self-update over plain HTTP is trivially MITM'd.
func cmdUpdate(args []string) error {
	o, _, err := parse("update", args)
	if err != nil {
		return err
	}
	if o.insecure {
		return errors.New("--insecure is not allowed for update: refusing to self-update over plain HTTP")
	}
	o.host = resolveHost(o.host, client.LoadStore())
	if o.host == "" {
		return usageErr("no server given: tunler update --host=tunler.example.com")
	}

	name := "tunler-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	base := "https://" + o.host + "/dl/" + name

	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		return fmt.Errorf("cannot locate own executable: %w", err)
	}

	// A server that gates downloads wants the master password as basic
	// auth, the same as the install script sends.
	master := o.masterPassword
	if master == "" {
		master = o.password // what TUNLER_PASSWORD meant before accounts had passwords
	}
	get := func(c *http.Client, url string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		if master != "" {
			req.SetBasicAuth("tunler", master)
		}
		resp, err := c.Do(req)
		if err == nil && resp.StatusCode == http.StatusUnauthorized {
			resp.Body.Close()
			return nil, errors.New("the server requires its master password for downloads: set TUNLER_MASTER_PASSWORD or pass --master-password")
		}
		return resp, err
	}

	sum, err := fetchString(get, base+".sha256")
	if err != nil {
		return fmt.Errorf("cannot fetch checksum from %s: %w", o.host, err)
	}
	fields := strings.Fields(sum)
	if len(fields) == 0 {
		return fmt.Errorf("empty checksum from %s", o.host)
	}
	published := fields[0]
	current, err := fileSHA256(self)
	if err != nil {
		return fmt.Errorf("cannot hash %s: %w", self, err)
	}
	if current == published {
		fmt.Printf("tunler %s is already up to date\n", version)
		return nil
	}

	fmt.Fprintf(os.Stderr, "downloading %s\n", base)
	tmp, err := download(get, base, filepath.Dir(self))
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer os.Remove(tmp)

	got, err := fileSHA256(tmp)
	if err != nil {
		return fmt.Errorf("cannot hash download: %w", err)
	}
	if got != published {
		return errors.New("checksum mismatch, aborting update")
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return fmt.Errorf("chmod failed: %w", err)
	}

	// Swap atomically. Windows cannot rename over a running executable, so the
	// old binary is moved aside first (works on Unix too).
	old := self + ".old"
	os.Remove(old)
	if err := os.Rename(self, old); err != nil {
		return fmt.Errorf("cannot replace %s: %w (hint: try with sudo)", self, err)
	}
	if err := os.Rename(tmp, self); err != nil {
		os.Rename(old, self) // restore
		return fmt.Errorf("cannot install new binary: %w", err)
	}
	os.Remove(old) // fails harmlessly on Windows while still running

	if out, err := exec.Command(self, "version").Output(); err == nil {
		fmt.Printf("updated: tunler %s -> %s", version, out)
	} else {
		fmt.Println("updated")
	}
	return nil
}

// getter performs a GET with c, adding whatever auth the server needs.
type getter func(c *http.Client, url string) (*http.Response, error)

func fetchString(get getter, url string) (string, error) {
	resp, err := get(&http.Client{Timeout: 30 * time.Second}, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(raw), err
}

// download fetches url into a temp file in dir (same filesystem as the
// binary, so the final rename is atomic).
func download(get getter, url, dir string) (string, error) {
	resp, err := get(&http.Client{Timeout: 5 * time.Minute}, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}
	f, err := os.CreateTemp(dir, ".tunler-update-*")
	if err != nil {
		return "", err
	}
	_, err = io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
