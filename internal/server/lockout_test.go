package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestLockoutBackoffNeverOverflows(t *testing.T) {
	srv := testServer(t)
	srv.loginMu.Lock()
	defer srv.loginMu.Unlock()
	l := &lockState{}
	// Walk far past the point where time.Minute<<over used to wrap negative.
	for i := 0; i < 100; i++ {
		srv.recordLoginFailure(l, "", "test")
		if l.fails < srv.cfg.Lockout.Threshold {
			continue
		}
		if wait := time.Until(l.until); wait <= 0 || wait > time.Duration(srv.cfg.Lockout.MaxBackoff) {
			t.Fatalf("after %d failures the lock runs %s", l.fails, wait)
		}
	}
}

func TestParallelLoginsCannotSlipPastLockout(t *testing.T) {
	srv := testServer(t)
	codes := make(chan int, 50)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- postLogin(srv, "me@x.nl", "wrong").Code
		}()
	}
	wg.Wait()
	close(codes)
	checked := 0
	for c := range codes {
		if c == http.StatusUnauthorized {
			checked++
		}
	}
	if checked != srv.cfg.Lockout.Threshold {
		t.Fatalf("%d parallel guesses were checked, want %d (the threshold)", checked, srv.cfg.Lockout.Threshold)
	}
}

func getDownload(srv *Server, password string) int {
	req := httptest.NewRequest(http.MethodGet, "http://tunler.example.com/install", nil)
	if password != "" {
		req.SetBasicAuth("tunler", password)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w.Code
}

func TestDownloadAuthSharesLockout(t *testing.T) {
	srv := testServer(t)
	srv.cfg.Downloads.RequireAuth = true

	if c := getDownload(srv, ""); c != http.StatusUnauthorized {
		t.Fatalf("no credentials: code = %d, want 401", c)
	}
	if c := getDownload(srv, "correct-password"); c != http.StatusOK {
		t.Fatalf("correct password: code = %d, want 200", c)
	}
	for i := 0; i < srv.cfg.Lockout.Threshold; i++ {
		if c := getDownload(srv, "wrong"); c != http.StatusUnauthorized {
			t.Fatalf("guess %d: code = %d, want 401", i+1, c)
		}
	}
	if c := getDownload(srv, "correct-password"); c != http.StatusTooManyRequests {
		t.Fatalf("download after lockout: code = %d, want 429", c)
	}
	if w := postLogin(srv, "me@x.nl", "correct-password"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("login after download guesses: code = %d, want 429", w.Code)
	}
}
