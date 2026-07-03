package server

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func newTestState(t *testing.T) *State {
	t.Helper()
	s, err := LoadState(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	return s
}

func TestValidDomain(t *testing.T) {
	// ValidDomain is syntactic only; reserved names are rejected by the server.
	valid := []string{"my-app", "a", "app2", "brave-otter-42"}
	invalid := []string{"", "-app", "app-", "My-App", "a.b", strings.Repeat("a", 64)}
	for _, d := range valid {
		if !ValidDomain(d) {
			t.Errorf("ValidDomain(%q) = false, want true", d)
		}
	}
	for _, d := range invalid {
		if ValidDomain(d) {
			t.Errorf("ValidDomain(%q) = true, want false", d)
		}
	}
}

func TestValidEmail(t *testing.T) {
	valid := []string{"me@example.com", "a.b+c@sub.domain.nl"}
	invalid := []string{"", "no-at.com", "@x.com", "a@b", "a b@c.com", "a@bc"}
	for _, e := range valid {
		if !ValidEmail(e) {
			t.Errorf("ValidEmail(%q) = false, want true", e)
		}
	}
	for _, e := range invalid {
		if ValidEmail(e) {
			t.Errorf("ValidEmail(%q) = true, want false", e)
		}
	}
}

func TestSecretLifecycle(t *testing.T) {
	s := newTestState(t)

	secret, err := s.AddSecret("me@x.nl")
	if err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	if len(secret) != 64 { // 32 bytes hex
		t.Fatalf("secret length = %d, want 64", len(secret))
	}

	if email, ok := s.UserBySecret(secret); !ok || email != "me@x.nl" {
		t.Fatalf("UserBySecret = %q, %v", email, ok)
	}
	if _, ok := s.UserBySecret("wrong"); ok {
		t.Fatal("wrong secret authorized")
	}
	if _, ok := s.UserBySecret(""); ok {
		t.Fatal("empty secret authorized")
	}

	// A second login must not invalidate the first machine's secret.
	secret2, _ := s.AddSecret("me@x.nl")
	if _, ok := s.UserBySecret(secret); !ok {
		t.Fatal("first secret revoked by second login")
	}

	if err := s.RevokeSecret(secret); err != nil {
		t.Fatalf("RevokeSecret: %v", err)
	}
	if _, ok := s.UserBySecret(secret); ok {
		t.Fatal("revoked secret still authorized")
	}
	if _, ok := s.UserBySecret(secret2); !ok {
		t.Fatal("revoking one secret revoked another")
	}
}

func TestDomainOwnership(t *testing.T) {
	s := newTestState(t)

	if newly, err := s.Claim("my-app", "alice@x.nl"); err != nil || !newly {
		t.Fatalf("first claim: newly=%v err=%v", newly, err)
	}
	if newly, err := s.Claim("my-app", "alice@x.nl"); err != nil || newly {
		t.Fatalf("re-claim by owner: newly=%v err=%v", newly, err)
	}
	if _, err := s.Claim("my-app", "eve@evil.com"); !errors.Is(err, ErrDomainTaken) {
		t.Fatalf("claim by another user: err=%v, want ErrDomainTaken", err)
	}

	if err := s.Release("my-app", "eve@evil.com"); !errors.Is(err, ErrDomainTaken) {
		t.Fatalf("release by non-owner: err=%v", err)
	}
	if err := s.Release("nope", "alice@x.nl"); !errors.Is(err, ErrDomainNotClaimed) {
		t.Fatalf("release of unclaimed: err=%v", err)
	}
	if err := s.Release("my-app", "alice@x.nl"); err != nil {
		t.Fatalf("release by owner: %v", err)
	}
	if _, err := s.Claim("my-app", "eve@evil.com"); err != nil {
		t.Fatalf("claim after release: %v", err)
	}
}

func TestDomainsFilter(t *testing.T) {
	s := newTestState(t)
	s.Claim("b-app", "alice@x.nl")
	s.Claim("a-app", "alice@x.nl")
	s.Claim("c-app", "bob@x.nl")

	all := s.Domains()
	if len(all) != 3 || all[0] != "a-app" { // sorted
		t.Fatalf("Domains() = %v", all)
	}
	alice := s.DomainsOf("alice@x.nl")
	if len(alice) != 2 || alice[0] != "a-app" || alice[1] != "b-app" {
		t.Fatalf("DomainsOf(alice) = %v", alice)
	}
}

func TestStatePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s1, _ := LoadState(path)
	secret, _ := s1.AddSecret("me@x.nl")
	s1.Claim("my-app", "me@x.nl")

	s2, err := LoadState(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if email, ok := s2.UserBySecret(secret); !ok || email != "me@x.nl" {
		t.Fatal("secret lost across reload")
	}
	if owner, ok := s2.Owner("my-app"); !ok || owner != "me@x.nl" {
		t.Fatal("domain ownership lost across reload")
	}
}
