package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jessegall/tunler/internal/protocol"
)

// liveServer runs srv on a real listener, with the listener's host as the
// base domain so control-plane routing matches.
func liveServer(t *testing.T) (*Server, string) {
	t.Helper()
	srv := testServer(t)
	srv.cfg.Domain = "127.0.0.1"
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return srv, strings.TrimPrefix(ts.URL, "http://")
}

// openControl performs the control handshake and returns the upgraded conn.
func openControl(t *testing.T, addr, domain, secret string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: tunler\r\n%s: %s\r\n%s: %s\r\n\r\n",
		protocol.ControlPath, protocol.HeaderDomain, domain, protocol.HeaderSecret, secret)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn, br, resp.StatusCode
}

func waitForTunnel(t *testing.T, srv *Server, domain string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		srv.mu.Lock()
		_, ok := srv.tunnels[domain]
		srv.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tunnel %q never registered", domain)
}

func TestUnresponsiveTunnelIsReplaced(t *testing.T) {
	probeTimeout = 100 * time.Millisecond
	defer func() { probeTimeout = 5 * time.Second }()
	srv, addr := liveServer(t)
	secret, _ := srv.state.AddSecret("alice@x.nl")

	stale, _, code := openControl(t, addr, "app", secret) // never answers pings
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("first control: %d", code)
	}
	waitForTunnel(t, srv, "app")
	if _, _, code := openControl(t, addr, "app", secret); code != http.StatusSwitchingProtocols {
		t.Fatalf("reconnect over a dead tunnel: code = %d, want 101", code)
	}
	stale.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := io.Copy(io.Discard, stale) // returns nil at EOF
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("stale control connection was not closed")
	}
}

func TestResponsiveTunnelIsKept(t *testing.T) {
	probeTimeout = time.Second
	defer func() { probeTimeout = 5 * time.Second }()
	srv, addr := liveServer(t)
	secret, _ := srv.state.AddSecret("alice@x.nl")

	live, br, _ := openControl(t, addr, "app", secret)
	go func() { // answer pings like a current client
		dec := json.NewDecoder(br)
		enc := json.NewEncoder(live)
		for {
			var msg protocol.Message
			if dec.Decode(&msg) != nil {
				return
			}
			if msg.Type == protocol.TypePing {
				enc.Encode(protocol.Message{Type: protocol.TypePong})
			}
		}
	}()
	waitForTunnel(t, srv, "app")
	if _, _, code := openControl(t, addr, "app", secret); code != http.StatusConflict {
		t.Fatalf("second control over a live tunnel: code = %d, want 409", code)
	}
}

func TestReleaseClosesLiveTunnel(t *testing.T) {
	srv, addr := liveServer(t)
	secret, _ := srv.state.AddSecret("alice@x.nl")
	conn, br, _ := openControl(t, addr, "app", secret)
	waitForTunnel(t, srv, "app")

	body := strings.NewReader(`{"domain":"app"}`)
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+protocol.ReleasePath, body)
	req.Header.Set(protocol.HeaderSecret, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("release: %v %v", resp, err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg protocol.Message
	if err := json.NewDecoder(br).Decode(&msg); err != nil || msg.Type != protocol.TypeClose {
		t.Fatalf("client got %+v, %v; want a close message", msg, err)
	}
	srv.mu.Lock()
	_, still := srv.tunnels["app"]
	srv.mu.Unlock()
	if still {
		t.Fatal("released domain still has a tunnel")
	}
}

func TestNewClaimTriggersOnClaim(t *testing.T) {
	srv, addr := liveServer(t)
	claimed := make(chan string, 2)
	srv.OnClaim = func(host string) { claimed <- host }
	secret, _ := srv.state.AddSecret("alice")

	conn, _, _ := openControl(t, addr, "fresh", secret)
	select {
	case host := <-claimed:
		if host != "fresh.127.0.0.1" {
			t.Fatalf("OnClaim(%q), want fresh.127.0.0.1", host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnClaim not called for a new domain")
	}
	conn.Close()

	// Reconnecting to an owned domain is not a new claim.
	waitGone := time.Now().Add(2 * time.Second)
	for time.Now().Before(waitGone) {
		srv.mu.Lock()
		_, up := srv.tunnels["fresh"]
		srv.mu.Unlock()
		if !up {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	openControl(t, addr, "fresh", secret)
	select {
	case host := <-claimed:
		t.Fatalf("OnClaim(%q) on a reconnect", host)
	case <-time.After(200 * time.Millisecond):
	}
}
