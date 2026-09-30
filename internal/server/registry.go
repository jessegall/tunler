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
	"strings"
	"sync"
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

// ValidEmail is a light sanity check, not RFC validation.
func ValidEmail(email string) bool {
	at := strings.Index(email, "@")
	return len(email) <= 254 && at > 0 && at < len(email)-3 &&
		strings.Contains(email[at:], ".") && !strings.ContainsAny(email, " \t\r\n")
}

// State persists users and domain ownership as a single JSON file.
//
//	users:   hex(sha256(secret)) -> email (a user may hold several secrets,
//	         one per `tunler login`, so machines don't invalidate each other)
//	domains: domain label -> owner email
type State struct {
	mu   sync.Mutex
	path string
	data stateData
}

type stateData struct {
	Users   map[string]string `json:"users"`
	Domains map[string]string `json:"domains"`
}

func LoadState(path string) (*State, error) {
	s := &State{path: path, data: stateData{
		Users:   map[string]string{},
		Domains: map[string]string{},
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
	return s, nil
}

// AddSecret mints a new secret for email and persists its hash.
func (s *State) AddSecret(email string) (string, error) {
	secret, err := randomToken(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashSecret(secret)
	s.data.Users[h] = email
	if err := s.save(); err != nil {
		delete(s.data.Users, h) // keep memory in step with disk
		return "", err
	}
	return secret, nil
}

// UserBySecret resolves a presented secret to the owning user's email.
func (s *State) UserBySecret(secret string) (string, bool) {
	if secret == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	email, ok := s.data.Users[hashSecret(secret)]
	return email, ok
}

// RevokeSecret removes one secret (logout).
func (s *State) RevokeSecret(secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashSecret(secret)
	email, ok := s.data.Users[h]
	if !ok {
		return nil
	}
	delete(s.data.Users, h)
	if err := s.save(); err != nil {
		s.data.Users[h] = email
		return err
	}
	return nil
}

// Owner returns the owner of domain, if claimed.
func (s *State) Owner(domain string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	email, ok := s.data.Domains[domain]
	return email, ok
}

// Claim assigns an unclaimed domain to email, or verifies existing
// ownership. newlyClaimed is true only when this call first claimed it,
// the atomic signal the server uses to gate cert issuance and Traefik sync.
func (s *State) Claim(domain, email string) (newlyClaimed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner, ok := s.data.Domains[domain]; ok {
		if owner != email {
			return false, ErrDomainTaken
		}
		return false, nil
	}
	s.data.Domains[domain] = email
	if err := s.save(); err != nil {
		delete(s.data.Domains, domain)
		return false, err
	}
	return true, nil
}

// Release unclaims a domain owned by email.
func (s *State) Release(domain, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.data.Domains[domain]
	if !ok {
		return ErrDomainNotClaimed
	}
	if owner != email {
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

// DomainsOf returns the domains owned by email, sorted.
func (s *State) DomainsOf(email string) []string { return s.domains(email) }

// domains returns claimed labels, filtered to email when non-empty, sorted.
func (s *State) domains(email string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.data.Domains))
	for d, owner := range s.data.Domains {
		if email == "" || owner == email {
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
