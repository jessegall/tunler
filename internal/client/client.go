// Package client speaks the tunler protocol: it authenticates with a tunler
// server, keeps a control connection open, and pipes proxied connections to a
// local target. Connection parameters come from flags, environment, and the
// saved login store.
package client

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jessegall/tunler/internal/protocol"
)

const (
	pingInterval = 25 * time.Second
	readTimeout  = 90 * time.Second
	dialTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
)

// apiClient bounds the JSON control requests so the CLI never hangs on a
// black-holed server.
var apiClient = &http.Client{Timeout: 30 * time.Second}

// Config holds the connection parameters for a tunnel. It is plain data,
// copied by value.
type Config struct {
	Host     string // tunler server, e.g. "tunler.example.com"
	Domain   string // subdomain label to claim, e.g. "my-app"
	Secret   string // user secret
	Target   string // local address to forward to, e.g. "127.0.0.1:8000"
	Auth     string // optional "user:pass" basic auth required from visitors
	Insecure bool   // plain HTTP to the server (local testing only)
}

func (c Config) scheme() string {
	if c.Insecure {
		return "http"
	}
	return "https"
}

// URL returns the public URL of the tunnel.
func (c Config) URL() string {
	return c.scheme() + "://" + c.Domain + "." + c.Host
}

// serverAddr returns host:port for dialing the server.
func (c Config) serverAddr() string {
	if _, _, err := net.SplitHostPort(c.Host); err == nil {
		return c.Host
	}
	if c.Insecure {
		return c.Host + ":80"
	}
	return c.Host + ":443"
}

func (c Config) dialServer() (net.Conn, error) {
	if c.Insecure {
		return net.DialTimeout("tcp", c.serverAddr(), dialTimeout)
	}
	d := &net.Dialer{Timeout: dialTimeout}
	return tls.DialWithDialer(d, "tcp", c.serverAddr(), &tls.Config{
		ServerName: stripPort(c.Host),
	})
}

// api performs a JSON request against a /_tunler endpoint. The secret (if
// any) is sent in the auth header; body may be nil; out may be nil for
// endpoints without a response body.
func (c Config) api(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	u := url.URL{Scheme: c.scheme(), Host: c.serverAddr(), Path: path}
	req, err := http.NewRequest(method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Secret != "" {
		req.Header.Set(protocol.HeaderSecret, c.Secret)
	}
	resp, err := apiClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New(readError(resp))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("bad server response: %w", err)
		}
	}
	return nil
}

// Login exchanges the master password for a user secret.
func Login(cfg Config, email, password string) (string, error) {
	var out protocol.LoginResponse
	err := cfg.api(http.MethodPost, protocol.LoginPath,
		protocol.LoginRequest{Email: email, Password: password}, &out)
	return out.Secret, err
}

// Logout revokes cfg.Secret server-side.
func Logout(cfg Config) error {
	return cfg.api(http.MethodPost, protocol.LogoutPath, nil, nil)
}

// Domains lists the domains owned by the authenticated user.
func Domains(cfg Config) ([]string, error) {
	var out protocol.DomainsResponse
	err := cfg.api(http.MethodGet, protocol.DomainsPath, nil, &out)
	return out.Domains, err
}

// Release unclaims a domain owned by the authenticated user.
func Release(cfg Config, domain string) error {
	return cfg.api(http.MethodPost, protocol.ReleasePath, protocol.ReleaseRequest{Domain: domain}, nil)
}

// AuthError marks a rejection of the domain/secret pair (no point retrying).
type AuthError struct{ msg string }

func (e *AuthError) Error() string { return e.msg }

// Run connects the control channel and serves the tunnel until the connection
// drops (returns the cause) or auth fails (returns *AuthError). ins may be nil
// to disable traffic inspection; onUp, if non-nil, is called once the tunnel
// is established.
func Run(cfg Config, ins *Inspector, onUp func()) error {
	var extra map[string]string
	if cfg.Auth != "" {
		extra = map[string]string{protocol.HeaderAuth: cfg.Auth}
	}
	conn, br, err := upgrade(cfg, protocol.ControlPath, extra)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("tunnel up: %s -> %s", cfg.URL(), cfg.Target)
	if onUp != nil {
		onUp()
	}

	var writeMu sync.Mutex
	enc := json.NewEncoder(conn)
	send := func(msg protocol.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		return enc.Encode(msg)
	}

	// Keepalive pinger; also detects a dead connection via write errors.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := send(protocol.Message{Type: protocol.TypePing}); err != nil {
					conn.Close()
					return
				}
			}
		}
	}()

	dec := json.NewDecoder(br)
	for {
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		var msg protocol.Message
		if err := dec.Decode(&msg); err != nil {
			return fmt.Errorf("control connection lost: %w", err)
		}
		switch msg.Type {
		case protocol.TypeOpen:
			go serveConn(cfg, ins, msg.ID)
		case protocol.TypePong:
			// read deadline already refreshed
		}
	}
}

// serveConn dials back a data connection for id and pipes it to the target.
func serveConn(cfg Config, ins *Inspector, id string) {
	remote, br, err := upgrade(cfg, protocol.DataPath, map[string]string{
		protocol.HeaderConnID: id,
	})
	if err != nil {
		log.Printf("data connection failed: %v", err)
		return
	}
	defer remote.Close()

	local, err := net.DialTimeout("tcp", cfg.Target, dialTimeout)
	if err != nil {
		log.Printf("cannot reach local target %s: %v", cfg.Target, err)
		return
	}
	defer local.Close()

	reqStream := io.MultiReader(bufferedBytes(br), remote) // visitor -> local
	var respStream io.Reader = local                       // local -> visitor

	// The inspector taps both directions through pipes; the relay stays a dumb
	// byte copy and never depends on HTTP parsing succeeding.
	if ins != nil {
		reqR, reqW := io.Pipe()
		respR, respW := io.Pipe()
		reqStream = io.TeeReader(reqStream, reqW)
		respStream = io.TeeReader(respStream, respW)
		go ins.observe(reqR, respR)
		defer reqW.Close()
		defer respW.Close()
	}

	done := make(chan struct{})
	go func() {
		io.Copy(remote, respStream)
		remote.Close()
		close(done)
	}()
	io.Copy(local, reqStream)
	if cw, ok := local.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	<-done
}

// bufferedBytes drains whatever the bufio.Reader already holds so no bytes
// read ahead of the raw connection are lost.
func bufferedBytes(br *bufio.Reader) io.Reader {
	n := br.Buffered()
	if n == 0 {
		return bytes.NewReader(nil)
	}
	buf, _ := br.Peek(n)
	return bytes.NewReader(buf)
}

// upgrade dials the server and switches path to the tunler protocol.
func upgrade(cfg Config, path string, extra map[string]string) (net.Conn, *bufio.Reader, error) {
	// The handshake headers are built by hand, so reject any value that could
	// inject extra header lines.
	values := []string{cfg.Host, cfg.Domain, cfg.Secret}
	for _, v := range extra {
		values = append(values, v)
	}
	for _, v := range values {
		if strings.ContainsAny(v, "\r\n") {
			return nil, nil, errors.New("invalid character in connection parameters")
		}
	}

	conn, err := cfg.dialServer()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot reach %s: %w", cfg.Host, err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", stripPort(cfg.Host))
	fmt.Fprintf(&b, "Connection: Upgrade\r\nUpgrade: %s\r\n", protocol.UpgradeProto)
	fmt.Fprintf(&b, "%s: %s\r\n", protocol.HeaderDomain, cfg.Domain)
	fmt.Fprintf(&b, "%s: %s\r\n", protocol.HeaderSecret, cfg.Secret)
	for k, v := range extra {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")

	conn.SetDeadline(time.Now().Add(dialTimeout))
	if _, err := conn.Write([]byte(b.String())); err != nil {
		conn.Close()
		return nil, nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("bad response from server: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		msg := readError(resp)
		conn.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return nil, nil, &AuthError{msg: msg}
		}
		return nil, nil, errors.New(msg)
	}
	conn.SetDeadline(time.Time{})
	return conn, br, nil
}

// readError extracts a human-readable message from an error response.
func readError(resp *http.Response) string {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e protocol.ErrorResponse
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return fmt.Sprintf("%s (%s)", e.Error, resp.Status)
	}
	return resp.Status
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
