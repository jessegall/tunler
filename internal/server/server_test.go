package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jessegall/tunler/internal/protocol"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Domain = "tunler.example.com"
	cfg.PasswordHash = mustHash(t, "correct-password")
	return New(cfg, newTestState(t))
}

// postLogin creates (or logs in to) account user with the account password
// "account-pw", passing master as the server master password.
func postLogin(srv *Server, user, master string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(protocol.LoginRequest{Username: user, Password: "account-pw", MasterPassword: master})
	req := httptest.NewRequest(http.MethodPost, "http://tunler.example.com"+protocol.LoginPath, bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestLogin(t *testing.T) {
	srv := testServer(t)

	if w := postLogin(srv, "me@x.nl", "wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: code = %d, want 401", w.Code)
	}

	w := postLogin(srv, "me@x.nl", "correct-password")
	if w.Code != http.StatusOK {
		t.Fatalf("login: code = %d, body %s", w.Code, w.Body)
	}
	var resp protocol.LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Secret == "" {
		t.Fatalf("bad login response: %s", w.Body)
	}
	if email, ok := srv.state.UserBySecret(resp.Secret); !ok || email != "me@x.nl" {
		t.Fatal("minted secret does not authorize")
	}

	if w := postLogin(srv, "Not Valid!", "correct-password"); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid username: code = %d, want 400", w.Code)
	}
}

func TestLoginLockout(t *testing.T) {
	srv := testServer(t)

	for i := 0; i < 5; i++ {
		if w := postLogin(srv, "me@x.nl", "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: code = %d, want 401", i+1, w.Code)
		}
	}
	// 5th failure arms the lockout: even the correct password is rejected.
	if w := postLogin(srv, "me@x.nl", "correct-password"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked out: code = %d, want 429", w.Code)
	}
}

func TestUnknownHostAndHealthz(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "http://other.example.org/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown host: code = %d, want 404", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "http://tunler.example.com/healthz", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: code = %d, want 200", w.Code)
	}
}

func TestTunnelAuthRejections(t *testing.T) {
	srv := testServer(t)
	secret, _ := srv.state.AddSecret("alice@x.nl")
	srv.state.Claim("owned", "bob@x.nl")

	cases := []struct {
		name           string
		domain, secret string
		want           int
	}{
		{"bad secret", "my-app", "nope", http.StatusUnauthorized},
		{"invalid domain", "Bad.Domain", secret, http.StatusBadRequest},
		{"reserved domain", "www", secret, http.StatusBadRequest},
		{"owned by other user", "owned", secret, http.StatusForbidden},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "http://tunler.example.com"+protocol.ControlPath, nil)
		req.Header.Set(protocol.HeaderDomain, c.domain)
		req.Header.Set(protocol.HeaderSecret, c.secret)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != c.want {
			t.Errorf("%s: code = %d, want %d", c.name, w.Code, c.want)
		}
	}
}

func TestSubdomainWithoutTunnel(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "http://my-app.tunler.example.com/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("no tunnel: code = %d, want 502", w.Code)
	}
}

func TestLockoutDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domain = "tunler.example.com"
	cfg.PasswordHash = mustHash(t, "correct-password")
	cfg.Lockout.Enabled = false
	srv := New(cfg, newTestState(t))

	for i := 0; i < 10; i++ {
		postLogin(srv, "me@x.nl", "wrong")
	}
	// With lockout off, the correct password still works after many failures.
	if w := postLogin(srv, "me@x.nl", "correct-password"); w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (no lockout)", w.Code)
	}
}

func TestRegistrationAllowlistLogin(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domain = "tunler.example.com"
	cfg.PasswordHash = mustHash(t, "correct-password")
	cfg.Registration = Registration{Mode: "allowlist", Allowlist: []string{"ok@x.nl"}}
	srv := New(cfg, newTestState(t))

	if w := postLogin(srv, "ok@x.nl", "correct-password"); w.Code != http.StatusOK {
		t.Fatalf("allowlisted: code = %d, want 200", w.Code)
	}
	if w := postLogin(srv, "nope@x.nl", "correct-password"); w.Code != http.StatusForbidden {
		t.Fatalf("non-allowlisted: code = %d, want 403", w.Code)
	}
}

func TestAllowHost(t *testing.T) {
	srv := testServer(t)
	srv.state.Claim("live", "me@x.nl")

	ok := []string{"tunler.example.com", "live.tunler.example.com"}
	bad := []string{"unclaimed.tunler.example.com", "a.b.tunler.example.com", "evil.com"}
	for _, h := range ok {
		if err := srv.AllowHost(context.Background(), h); err != nil {
			t.Errorf("AllowHost(%q) = %v, want nil", h, err)
		}
	}
	for _, h := range bad {
		if err := srv.AllowHost(context.Background(), h); err == nil {
			t.Errorf("AllowHost(%q) = nil, want error", h)
		}
	}
}

func TestTunnelAcquire(t *testing.T) {
	t.Run("unlimited", func(t *testing.T) {
		tn := &tunnel{}
		for i := 0; i < 100; i++ {
			if _, ok := tn.acquire(); !ok {
				t.Fatal("unlimited tunnel refused a connection")
			}
		}
	})
	t.Run("capped", func(t *testing.T) {
		tn := &tunnel{sem: make(chan struct{}, 2)}
		r1, ok1 := tn.acquire()
		_, ok2 := tn.acquire()
		if !ok1 || !ok2 {
			t.Fatal("first two acquires should succeed")
		}
		if _, ok := tn.acquire(); ok {
			t.Fatal("third acquire should be refused at cap 2")
		}
		r1() // free a slot
		if _, ok := tn.acquire(); !ok {
			t.Fatal("acquire should succeed after release")
		}
	})
}
