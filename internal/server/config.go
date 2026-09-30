package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Config is the full server configuration. The command layer assembles it
// from defaults, an optional JSON file, environment, and flags (in
// increasing order of precedence); every field is plain data.
type Config struct {
	Domain       string       `json:"domain"`
	Email        string       `json:"email"`         // Let's Encrypt contact (optional)
	PasswordHash string       `json:"password_hash"` // bcrypt; a legacy hex(sha256) still verifies
	DataDir      string       `json:"data_dir"`
	BinDir       string       `json:"bin_dir"`      // client binaries served at /install and /dl/
	TraefikFile  string       `json:"traefik_file"` // dynamic-config file to regenerate (optional)
	Reserved     []string     `json:"reserved"`     // subdomains that can never be claimed
	Downloads    Downloads    `json:"downloads"`
	Limits       Limits       `json:"limits"`
	Lockout      Lockout      `json:"lockout"`
	Registration Registration `json:"registration"`
	SMTP         SMTP         `json:"smtp"`
}

// SMTP configures the mail server that sends login codes. With a Host set,
// every login is confirmed by a code emailed to the address, so the master
// password alone cannot log in as someone else. Without it, anyone with the
// master password can log in as any email.
type SMTP struct {
	Host     string `json:"host"`
	Port     int    `json:"port"` // 587 (STARTTLS) by default; 465 means implicit TLS
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"` // sender address
}

// Enabled reports whether logins are confirmed by email.
func (m SMTP) Enabled() bool { return m.Host != "" }

// Downloads controls the /install and /dl/ endpoints.
type Downloads struct {
	// RequireAuth gates client downloads behind the master password.
	RequireAuth bool `json:"require_auth"`
}

// Limits bounds per-request and per-tunnel resource use.
type Limits struct {
	MaxBodyBytes          int64    `json:"max_body_bytes"`          // proxied request body cap; 0 = unlimited
	MaxConnsPerTunnel     int      `json:"max_conns_per_tunnel"`    // concurrent data connections; 0 = unlimited
	ResponseHeaderTimeout Duration `json:"response_header_timeout"` // time the local app has to start responding
	DataConnIdleTimeout   Duration `json:"data_conn_idle_timeout"`  // drop a data connection idle this long
}

// Lockout configures login brute-force protection. With Traefik TCP
// passthrough the visitor IP is not recoverable, so the backoff is global.
type Lockout struct {
	Enabled    bool     `json:"enabled"`
	Threshold  int      `json:"threshold"`   // consecutive failures before locking
	MaxBackoff Duration `json:"max_backoff"` // cap on the escalating lock window
}

// Registration controls who may create an account via login.
type Registration struct {
	Mode      string   `json:"mode"`      // "open" (any email) or "allowlist"
	Allowlist []string `json:"allowlist"` // permitted emails when Mode == "allowlist"
}

// DefaultConfig returns the built-in defaults that every config starts from.
func DefaultConfig() Config {
	return Config{
		Reserved:  []string{"www", "mail", "ftp", "admin", "tunler"},
		Downloads: Downloads{RequireAuth: false},
		Limits: Limits{
			MaxBodyBytes:          0,
			MaxConnsPerTunnel:     64,
			ResponseHeaderTimeout: Duration(30 * time.Second),
			DataConnIdleTimeout:   Duration(5 * time.Minute),
		},
		Lockout:      Lockout{Enabled: true, Threshold: 5, MaxBackoff: Duration(15 * time.Minute)},
		Registration: Registration{Mode: "open"},
	}
}

// LoadConfig overlays the JSON file at path onto DefaultConfig. An empty
// path returns the defaults; only keys present in the file override them,
// since json.Unmarshal merges into the pre-seeded value.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, nil
}

// HashPassword returns the bcrypt hash of a master password, the form kept in
// PasswordHash, so plaintext need not be stored and a leaked hash is slow to
// crack. The password is pre-hashed to hex SHA-256 so bcrypt's 72-byte input
// limit never truncates or rejects a long password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(sha256Hex(password)), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// bcryptCost is a variable so tests can use the cheapest cost.
var bcryptCost = bcrypt.DefaultCost

// VerifyPassword reports whether password matches hash. It accepts both the
// bcrypt form HashPassword produces and the legacy unsalted hex SHA-256 form,
// so configs written by older versions keep working.
func VerifyPassword(password, hash string) bool {
	if strings.HasPrefix(hash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(sha256Hex(password))) == nil
	}
	return subtle.ConstantTimeCompare([]byte(sha256Hex(password)), []byte(hash)) == 1
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// allowsEmail reports whether email may register under this configuration.
func (r Registration) allowsEmail(email string) bool {
	if r.Mode != "allowlist" {
		return true
	}
	for _, e := range r.Allowlist {
		if e == email {
			return true
		}
	}
	return false
}

// Duration is a time.Duration that marshals to/from a Go duration string
// ("30s", "5m") so config files read naturally.
type Duration time.Duration

func (d Duration) String() string { return time.Duration(d).String() }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}
