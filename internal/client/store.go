package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Store is the persisted login state (~/.config/tunler/config.json).
// Explicit flags and env vars always take precedence over it; it only
// exists so `tunler login` makes later commands flag-free.
type Store struct {
	DefaultHost string               `json:"default_host,omitempty"`
	Hosts       map[string]HostCreds `json:"hosts,omitempty"`
}

// HostCreds is a saved login for one tunler server.
type HostCreds struct {
	User   string `json:"user"`
	Email  string `json:"email,omitempty"` // old name of User, read on load
	Secret string `json:"secret"`

	// Ephemeral remembers the random domains used for tunnels started
	// without --domain, so they are reused instead of minting (and making
	// the server fetch a certificate for) a new name every time.
	Ephemeral []string `json:"ephemeral,omitempty"`
}

// configDir returns the tunler config directory (~/.config/tunler et al.).
func configDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tunler"), nil
}

func storePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// InstalledHost returns the server the client was installed from. The
// install script writes it next to the config file, binding the binary to
// its download source. Reinstalling from another server overwrites it.
func InstalledHost() string {
	dir, err := configDir()
	if err != nil {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(dir, "server"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// LoadStore reads the saved state; a missing file yields an empty store.
func LoadStore() Store {
	s := Store{Hosts: map[string]HostCreds{}}
	path, err := storePath()
	if err != nil {
		return s
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	json.Unmarshal(raw, &s)
	if s.Hosts == nil {
		s.Hosts = map[string]HostCreds{}
	}
	for host, c := range s.Hosts {
		if c.User == "" && c.Email != "" {
			c.User, c.Email = c.Email, ""
			s.Hosts[host] = c
		}
	}
	return s
}

// Save persists the store with owner-only permissions.
func (s Store) Save() error {
	path, err := storePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}
