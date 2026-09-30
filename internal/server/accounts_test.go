package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jessegall/tunler/internal/protocol"
)

func login(srv *Server, req protocol.LoginRequest) (*httptest.ResponseRecorder, protocol.ErrorResponse) {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "http://tunler.example.com"+protocol.LoginPath, bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	var e protocol.ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &e)
	return w, e
}

func TestAccountLoginNeedsOwnPasswordNotMaster(t *testing.T) {
	srv := testServer(t)
	if w := postLogin(srv, "alice", "correct-password"); w.Code != http.StatusOK {
		t.Fatalf("create: code = %d (%s)", w.Code, w.Body)
	}
	// From another machine: username and account password, no master.
	if w, _ := login(srv, protocol.LoginRequest{Username: "Alice", Password: "account-pw"}); w.Code != http.StatusOK {
		t.Fatalf("login with own password: code = %d (%s)", w.Code, w.Body)
	}
	// The master password is no way into someone's account.
	if w, _ := login(srv, protocol.LoginRequest{Username: "alice", Password: "correct-password", MasterPassword: "correct-password"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("master password as account password: code = %d, want 401", w.Code)
	}
}

func TestCreatingAccountAsksForMasterPassword(t *testing.T) {
	srv := testServer(t)
	w, e := login(srv, protocol.LoginRequest{Username: "bob", Password: "account-pw"})
	if w.Code != http.StatusUnauthorized || e.Code != protocol.CodeMasterPasswordRequired {
		t.Fatalf("new account without master: code = %d, %+v", w.Code, e)
	}
	if w, _ := login(srv, protocol.LoginRequest{Username: "bob", Password: "short", MasterPassword: "correct-password"}); w.Code != http.StatusBadRequest {
		t.Fatalf("short password: code = %d, want 400", w.Code)
	}
	if w, _ := login(srv, protocol.LoginRequest{Password: "correct-password"}); w.Code != http.StatusBadRequest {
		t.Fatalf("old client without username: code = %d, want 400", w.Code)
	}
}

func TestAccountLockoutIsPerUser(t *testing.T) {
	srv := testServer(t)
	postLogin(srv, "alice", "correct-password")
	postLogin(srv, "bob", "correct-password")
	for i := 0; i < srv.cfg.Lockout.Threshold; i++ {
		login(srv, protocol.LoginRequest{Username: "alice", Password: "guess"})
	}
	if w, _ := login(srv, protocol.LoginRequest{Username: "alice", Password: "account-pw"}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("alice after guesses: code = %d, want 429", w.Code)
	}
	if w, _ := login(srv, protocol.LoginRequest{Username: "bob", Password: "account-pw"}); w.Code != http.StatusOK {
		t.Fatalf("bob while alice is locked: code = %d, want 200", w.Code)
	}
}

func TestExpireRemovesAccountDomainsAndTunnels(t *testing.T) {
	srv, addr := liveServer(t)
	idleSecret, _ := srv.state.CreateUser("idle", mustHash(t, "account-pw"))
	busySecret, _ := srv.state.CreateUser("busy", mustHash(t, "account-pw"))
	srv.state.Claim("idle-app", "idle")
	openControl(t, addr, "idle-app", idleSecret)
	openControl(t, addr, "busy-app", busySecret)
	waitForTunnel(t, srv, "idle-app")
	waitForTunnel(t, srv, "busy-app")

	// Both accounts look idle for 40 days; only busy has a live tunnel,
	// which counts as activity. The idle one's tunnel was closed first.
	srv.closeTunnel("idle-app", "test")
	old := time.Now().Add(-40 * 24 * time.Hour).Unix()
	srv.state.mu.Lock()
	srv.state.data.Seen["idle"], srv.state.data.Seen["busy"] = old, old
	srv.state.mu.Unlock()

	srv.ExpireAccounts()

	if _, ok := srv.state.UserPassword("idle"); ok {
		t.Error("idle account still exists")
	}
	if _, ok := srv.state.Owner("idle-app"); ok {
		t.Error("idle account's domain still claimed")
	}
	if _, ok := srv.state.UserBySecret(idleSecret); ok {
		t.Error("idle account's secret still works")
	}
	if _, ok := srv.state.UserPassword("busy"); !ok {
		t.Error("account with a live tunnel was expired")
	}
	// The name is free again.
	if _, err := srv.state.CreateUser("idle", mustHash(t, "new-pw")); err != nil {
		t.Errorf("recreating an expired username: %v", err)
	}
}

func TestLegacyStateStartsExpiryClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte(`{"users":{"h":"me@x.nl"},"domains":{"app":"me@x.nl"}}`), 0o600)
	s, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if released, _ := s.Expire(24 * time.Hour); len(released) != 0 {
		t.Fatalf("legacy account expired on the first sweep: %v", released)
	}
}
