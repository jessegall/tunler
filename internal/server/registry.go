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
	s.data.Users[hashSecret(secret)] = email
	return secret, s.save()
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
	delete(s.data.Users, hashSecret(secret))
	return s.save()
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
	return true, s.save()
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
	return s.save()
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
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
