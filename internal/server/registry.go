package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// domainLabel validates a single DNS label: lowercase alphanumerics and
// hyphens, no leading/trailing hyphen, max 63 chars.
var domainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Domain-ownership errors, surfaced to callers via errors.Is.
var (
	ErrDomainTaken      = errors.New("domain is owned by another user")
	ErrDomainNotClaimed = errors.New("domain is not claimed")
)

// ValidDomain reports whether label is a syntactically valid subdomain. The
// reserved-name check is applied separately by the server from its config.
func ValidDomain(label string) bool {
	return domainLabel.MatchString(label)
}

// username: lowercase letters, digits and . _ @ + -, starting and ending
// with a letter or digit. Email addresses fit, so accounts made by older
// clients (which logged in by user) stay valid.
var username = regexp.MustCompile(`^[a-z0-9]([a-z0-9._@+-]{0,62}[a-z0-9])?$`)

// ValidUsername reports whether name is an acceptable account name. Callers
// lowercase it first.
func ValidUsername(name string) bool {
	return username.MatchString(name)
}

// State persists users and domain ownership as a single JSON file.
//
//	passwords: username -> bcrypt hash of the user's own password
//	users:   hex(sha256(secret)) -> username (a user may hold several
//	         secrets, one per machine, so machines don't invalidate each other)
//	domains: domain label -> owner username
//	seen:    username -> last activity (unix seconds), for account expiry
type State struct {
	mu   sync.Mutex
	path string
	data stateData
}

type stateData struct {
	Passwords map[string]string `json:"passwords"`
	Users     map[string]string `json:"users"`
	Domains   map[string]string `json:"domains"`
	Seen      map[string]int64  `json:"seen"`
}

// ErrUserTaken means an account with that username already exists.
var ErrUserTaken = errors.New("username is taken")

// seenGranularity bounds how often activity is written to disk.
const seenGranularity = time.Hour

func LoadState(path string) (*State, error) {
	s := &State{path: path, data: stateData{
		Passwords: map[string]string{},
		Users:     map[string]string{},
		Domains:   map[string]string{},
		Seen:      map[string]int64{},
	}}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("corrupt state file %s: %w", path, err)
	}
	if s.data.Passwords == nil {
		s.data.Passwords = map[string]string{}
	}
	if s.data.Seen == nil {
		s.data.Seen = map[string]int64{}
	}
	// Accounts from before expiry existed start their clock now rather than
	// expiring on the first sweep.
	now := time.Now().Unix()
	for _, users := range []map[string]string{s.data.Users, s.data.Domains} {
		for _, u := range users {
			if _, ok := s.data.Seen[u]; !ok {
				s.data.Seen[u] = now
			}
		}
	}
	return s, nil
}

// CreateUser creates an account with the given password hash and mints its
// first secret. It refuses a username that already has an account.
// Accounts made before per-user passwords have none, so the first login
// from a current client gives them one.
func (s *State) CreateUser(user, passwordHash string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Passwords[user]; ok {
		return "", ErrUserTaken
	}
	s.data.Passwords[user] = passwordHash
	secret, err := s.addSecretLocked(user)
	if err != nil {
		delete(s.data.Passwords, user)
	}
	return secret, err
}

// UserPassword returns the password hash of user's account, if it exists.
func (s *State) UserPassword(user string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.data.Passwords[user]
	return hash, ok
}

// AddSecret mints a new secret for user and persists its hash.
func (s *State) AddSecret(user string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addSecretLocked(user)
}

func (s *State) addSecretLocked(user string) (string, error) {
	secret, err := randomToken(32)
	if err != nil {
		return "", err
	}
	h := hashSecret(secret)
	prevSeen, hadSeen := s.data.Seen[user]
	s.data.Users[h] = user
	s.data.Seen[user] = time.Now().Unix()
	if err := s.save(); err != nil {
		delete(s.data.Users, h) // keep memory in step with disk
		if hadSeen {
			s.data.Seen[user] = prevSeen
		} else {
			delete(s.data.Seen, user)
		}
		return "", err
	}
	return secret, nil
}

// Touch records activity for user, writing it at most once per
// seenGranularity.
func (s *State) Touch(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(time.Unix(s.data.Seen[user], 0)) < seenGranularity {
		return
	}
	s.data.Seen[user] = now.Unix()
	s.save() // best effort: at worst the account looks idle an hour longer
}

// Expire removes every account idle longer than maxAge: its password, its
// secrets, its domains and its activity record. It returns the released domains.
func (s *State) Expire(maxAge time.Duration) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge).Unix()
	gone := map[string]bool{}
	for u, at := range s.data.Seen {
		if at < cutoff {
			gone[u] = true
		}
	}
	if len(gone) == 0 {
		return nil, nil
	}
	backup := s.data.clone()
	var released []string
	for h, u := range s.data.Users {
		if gone[u] {
			delete(s.data.Users, h)
		}
	}
	for d, u := range s.data.Domains {
		if gone[u] {
			delete(s.data.Domains, d)
			released = append(released, d)
		}
	}
	for u := range gone {
		delete(s.data.Seen, u)
		delete(s.data.Passwords, u)
	}
	if err := s.save(); err != nil {
		s.data = backup // keep memory in step with disk
		return nil, err
	}
	sort.Strings(released)
	return released, nil
}

func (d stateData) clone() stateData {
	c := stateData{Passwords: map[string]string{}, Users: map[string]string{}, Domains: map[string]string{}, Seen: map[string]int64{}}
	for k, v := range d.Passwords {
		c.Passwords[k] = v
	}
	for k, v := range d.Users {
		c.Users[k] = v
	}
	for k, v := range d.Domains {
		c.Domains[k] = v
	}
	for k, v := range d.Seen {
		c.Seen[k] = v
	}
	return c
}

// UserBySecret resolves a presented secret to the owning user's user.
func (s *State) UserBySecret(secret string) (string, bool) {
	if secret == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.data.Users[hashSecret(secret)]
	return user, ok
}

// RevokeSecret removes one secret (logout).
func (s *State) RevokeSecret(secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashSecret(secret)
	user, ok := s.data.Users[h]
	if !ok {
		return nil
	}
	delete(s.data.Users, h)
	if err := s.save(); err != nil {
		s.data.Users[h] = user
		return err
	}
	return nil
}

// Owner returns the owner of domain, if claimed.
func (s *State) Owner(domain string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.data.Domains[domain]
	return user, ok
}

// Claim assigns an unclaimed domain to user, or verifies existing
// ownership. newlyClaimed is true only when this call first claimed it,
// the atomic signal the server uses to gate cert issuance and Traefik sync.
func (s *State) Claim(domain, user string) (newlyClaimed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner, ok := s.data.Domains[domain]; ok {
		if owner != user {
			return false, ErrDomainTaken
		}
		return false, nil
	}
	s.data.Domains[domain] = user
	if err := s.save(); err != nil {
		delete(s.data.Domains, domain)
		return false, err
	}
	return true, nil
}

// Release unclaims a domain owned by user.
func (s *State) Release(domain, user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.data.Domains[domain]
	if !ok {
		return ErrDomainNotClaimed
	}
	if owner != user {
		return ErrDomainTaken
	}
	delete(s.data.Domains, domain)
	if err := s.save(); err != nil {
		s.data.Domains[domain] = owner
		return err
	}
	return nil
}

// Domains returns every claimed domain label, sorted.
func (s *State) Domains() []string { return s.domains("") }

// DomainsOf returns the domains owned by user, sorted.
func (s *State) DomainsOf(user string) []string { return s.domains(user) }

// domains returns claimed labels, filtered to user when non-empty, sorted.
func (s *State) domains(user string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.data.Domains))
	for d, owner := range s.data.Domains {
		if user == "" || owner == user {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// save must be called with s.mu held.
func (s *State) save() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.path, raw, 0o600)
}

// writeFileAtomic replaces path with data so a crash leaves either the old
// or the new file, never a truncated one: the data is synced before the
// rename, and the rename is synced after it.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, perm)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync() // best effort: not every platform can sync a directory
		d.Close()
	}
	return nil
}
