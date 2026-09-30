package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/jessegall/tunler/internal/protocol"
)

// fakeMailer records sent mail instead of sending it.
type fakeMailer struct{ bodies []string }

func (m *fakeMailer) Send(_, _, body string) error {
	m.bodies = append(m.bodies, body)
	return nil
}

func (m *fakeMailer) lastCode(t *testing.T) string {
	t.Helper()
	if len(m.bodies) == 0 {
		t.Fatal("no login code was mailed")
	}
	return regexp.MustCompile(`\d{6}`).FindString(m.bodies[len(m.bodies)-1])
}

func postJSON(srv *Server, path string, v any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(v)
	req := httptest.NewRequest(http.MethodPost, "http://tunler.example.com"+path, bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func verifyingServer(t *testing.T) (*Server, *fakeMailer) {
	srv := testServer(t)
	m := &fakeMailer{}
	srv.mailer = m
	return srv, m
}

func startLogin(t *testing.T, srv *Server, email string) string {
	t.Helper()
	w := postJSON(srv, protocol.LoginPath, protocol.LoginRequest{Email: email, Password: "correct-password", Verify: true})
	if w.Code != http.StatusAccepted {
		t.Fatalf("login: code = %d, want 202 (%s)", w.Code, w.Body)
	}
	var resp protocol.LoginResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Pending == "" || resp.Secret != "" {
		t.Fatalf("login response = %+v, want only a pending ID", resp)
	}
	return resp.Pending
}

func TestEmailConfirmedLogin(t *testing.T) {
	srv, m := verifyingServer(t)
	pending := startLogin(t, srv, "alice@x.nl")

	if w := postJSON(srv, protocol.LoginVerifyPath, protocol.LoginVerifyRequest{Pending: pending, Code: "000000x"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: code = %d, want 401", w.Code)
	}
	w := postJSON(srv, protocol.LoginVerifyPath, protocol.LoginVerifyRequest{Pending: pending, Code: m.lastCode(t)})
	if w.Code != http.StatusOK {
		t.Fatalf("verify: code = %d (%s)", w.Code, w.Body)
	}
	var resp protocol.LoginResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if email, ok := srv.state.UserBySecret(resp.Secret); !ok || email != "alice@x.nl" {
		t.Fatal("verified login did not mint a secret for alice")
	}
	// A code works once.
	if w := postJSON(srv, protocol.LoginVerifyPath, protocol.LoginVerifyRequest{Pending: pending, Code: m.lastCode(t)}); w.Code != http.StatusUnauthorized {
		t.Fatalf("reused code: code = %d, want 401", w.Code)
	}
}

func TestEmailConfirmedLoginRejectsOldClients(t *testing.T) {
	srv, _ := verifyingServer(t)
	if w := postLogin(srv, "alice@x.nl", "correct-password"); w.Code != http.StatusBadRequest {
		t.Fatalf("client without verify: code = %d, want 400", w.Code)
	}
}

func TestLoginCodeGuessesAreLimited(t *testing.T) {
	srv, m := verifyingServer(t)
	pending := startLogin(t, srv, "alice@x.nl")
	code := m.lastCode(t)
	for i := 0; i < codeAttempts; i++ {
		postJSON(srv, protocol.LoginVerifyPath, protocol.LoginVerifyRequest{Pending: pending, Code: "wrong"})
	}
	if w := postJSON(srv, protocol.LoginVerifyPath, protocol.LoginVerifyRequest{Pending: pending, Code: code}); w.Code != http.StatusUnauthorized {
		t.Fatalf("right code after %d wrong ones: code = %d, want 401", codeAttempts, w.Code)
	}
}

func TestLoginCodesPerHourAreLimited(t *testing.T) {
	srv, _ := verifyingServer(t)
	for i := 0; i < codesPerHour; i++ {
		startLogin(t, srv, "alice@x.nl")
	}
	w := postJSON(srv, protocol.LoginPath, protocol.LoginRequest{Email: "alice@x.nl", Password: "correct-password", Verify: true})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("code %d for one address: code = %d, want 429", codesPerHour+1, w.Code)
	}
}
