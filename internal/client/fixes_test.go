package client

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jessegall/tunler/internal/protocol"
)

// relayed feeds request and response bytes through taps the way serveConn
// does, and reports whether every write went through without blocking.
func relayed(t *testing.T, writes func(req, resp io.Writer)) {
	t.Helper()
	ins := NewInspector()
	reqTap, respTap := newTap(), newTap()
	go ins.observe(reqTap, respTap)
	done := make(chan struct{})
	go func() {
		writes(reqTap, respTap)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay stalled on the inspector")
	}
	reqTap.Close()
	respTap.Close()
}

func TestInspectorDoesNotStallOnInterimResponse(t *testing.T) {
	relayed(t, func(req, resp io.Writer) {
		io.WriteString(req, "POST /up HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello")
		io.WriteString(resp, "HTTP/1.1 100 Continue\r\n\r\n")
		time.Sleep(20 * time.Millisecond)
		io.WriteString(resp, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
}

func TestInspectorDoesNotStallOnEarlyResponse(t *testing.T) {
	relayed(t, func(req, resp io.Writer) {
		io.WriteString(req, "POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\npartial")
		io.WriteString(resp, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	})
}

func TestInspectorGivesUpInsteadOfBuffering(t *testing.T) {
	relayed(t, func(req, resp io.Writer) {
		// The request body never completes, so the response side can never
		// be parsed; the tap must drop it rather than grow without bound.
		io.WriteString(req, "POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\n")
		chunk := strings.Repeat("x", 64<<10)
		for i := 0; i < 2*maxTapBuffer/len(chunk); i++ {
			io.WriteString(resp, chunk)
		}
	})
}

func TestInspectorSkipsInterimResponse(t *testing.T) {
	ins := NewInspector()
	ins.observe(
		strings.NewReader("POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"),
		strings.NewReader("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"))
	ex := ins.snapshot()
	if len(ex) != 1 || ex[0].StatusCode != http.StatusCreated {
		t.Fatalf("recorded %+v, want one exchange answered 201", ex)
	}
}

func TestInspectorRejectsForeignHost(t *testing.T) {
	h := localOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for host, want := range map[string]int{
		"127.0.0.1:4646":    http.StatusOK,
		"localhost:4646":    http.StatusOK,
		"[::1]:4646":        http.StatusOK,
		"evil.example:4646": http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/exchanges", nil)
		req.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("Host %s: code = %d, want %d", host, w.Code, want)
		}
	}
}

func TestLoginWithEmailedCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case protocol.LoginPath:
			var req protocol.LoginRequest
			json.NewDecoder(r.Body).Decode(&req)
			if !req.Verify {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(protocol.LoginResponse{Pending: "p1"})
		case protocol.LoginVerifyPath:
			var req protocol.LoginVerifyRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.Pending != "p1" || req.Code != "123456" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(protocol.LoginResponse{Secret: "s3cret"})
		}
	}))
	defer srv.Close()
	cfg := Config{Host: strings.TrimPrefix(srv.URL, "http://"), Insecure: true}

	secret, err := Login(cfg, "me@x.nl", "pw", func() (string, error) { return " 123456\n", nil })
	if err != nil || secret != "s3cret" {
		t.Fatalf("Login = %q, %v; want s3cret", secret, err)
	}
	if _, err := Login(cfg, "me@x.nl", "pw", func() (string, error) { return "", errors.New("no tty") }); err == nil {
		t.Fatal("Login succeeded without a code")
	}
}

func TestBadRequestIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: "invalid or reserved domain"})
	}))
	defer srv.Close()
	cfg := Config{Host: strings.TrimPrefix(srv.URL, "http://"), Domain: "admin", Secret: "s", Insecure: true}
	var authErr *AuthError
	if err := Run(cfg, nil, nil); !errors.As(err, &authErr) || authErr.Status != http.StatusBadRequest {
		t.Fatalf("Run = %v, want a permanent 400 rejection", err)
	}
}
