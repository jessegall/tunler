// Package server implements tunlerd: the public-facing half of tunler.
//
// It terminates TLS for *.<base-domain>, routes each request by subdomain to
// the matching connected tunnel client, and speaks the upgrade protocol
// defined in internal/protocol with those clients. It deliberately keeps no
// record of proxied traffic: no request paths, headers, bodies, or byte
// counts are logged or persisted.
package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/jessegall/tunler/internal/protocol"
)

const (
	readTimeout  = 90 * time.Second
	dialTimeout  = 15 * time.Second
	writeTimeout = 10 * time.Second
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

// loginFailDelay slows every failed login to blunt brute-forcing. It is a
// variable so tests can disable the delay.
var loginFailDelay = time.Second

// Server routes public traffic to connected tunnel clients.
type Server struct {
	cfg      Config
	state    *State
	reserved map[string]bool // cfg.Reserved as a set

	mu      sync.Mutex
	tunnels map[string]*tunnel // active tunnels by domain label

	// Login lockout. With Traefik TCP passthrough the visitor IP is not
	// recoverable, so the backoff is global; see Config.Lockout.
	loginMu    sync.Mutex
	loginFails int
	loginLock  time.Time

	proxy *httputil.ReverseProxy
}

// tunnel is one connected client holding a domain.
type tunnel struct {
	domain string
	auth   string        // optional "user:pass" required from visitors
	conn   net.Conn      // the control connection
	sem    chan struct{} // concurrent-data-connection limiter; nil = unlimited

	writeMu sync.Mutex // serializes framed writes to conn/enc
	enc     *json.Encoder

	mu      sync.Mutex               // guards pending + closed
	pending map[string]chan net.Conn // conn ID -> waiting dialTunnel call
	closed  bool
}

// New builds a server from a resolved config and state store.
func New(cfg Config, state *State) *Server {
	reserved := make(map[string]bool, len(cfg.Reserved))
	for _, r := range cfg.Reserved {
		reserved[r] = true
	}
	s := &Server{
		cfg:      cfg,
		state:    state,
		reserved: reserved,
		tunnels:  map[string]*tunnel{},
	}
	s.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// URL.Host carries the tunnel label; dialTunnel resolves it to a
			// data connection. The original Host header is preserved so the
			// local app sees the public URL (important for OAuth callbacks).
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Context().Value(labelKey{}).(string)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		Transport: &http.Transport{
			DialContext:           s.dialTunnel,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       60 * time.Second,
			ResponseHeaderTimeout: time.Duration(cfg.Limits.ResponseHeaderTimeout),
		},
		FlushInterval: -1, // flush immediately: keeps SSE/streaming responsive
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "tunler: "+err.Error(), http.StatusBadGateway)
		},
	}
	return s
}

type labelKey struct{}

// ServeHTTP is the single entry point for all traffic on 80/443.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)

	switch {
	case host == s.cfg.Domain:
		s.serveControlPlane(w, r)
	case strings.HasSuffix(host, "."+s.cfg.Domain):
		label := strings.TrimSuffix(host, "."+s.cfg.Domain)
		if strings.Contains(label, ".") {
			http.Error(w, "unknown host", http.StatusNotFound)
			return
		}
		s.serveTunnel(w, r, label)
	default:
		http.Error(w, "unknown host", http.StatusNotFound)
	}
}

// serveControlPlane handles requests to the base domain itself.
func (s *Server) serveControlPlane(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case protocol.LoginPath:
		s.handleLogin(w, r)
	case protocol.LogoutPath:
		s.handleLogout(w, r)
	case protocol.DomainsPath:
		s.handleDomains(w, r)
	case protocol.ReleasePath:
		s.handleRelease(w, r)
	case protocol.ControlPath:
		s.handleControl(w, r)
	case protocol.DataPath:
		s.handleData(w, r)
	case "/install", "/install.sh":
		s.handleInstall(w, r)
	case "/healthz":
		fmt.Fprintln(w, "ok")
	case "/":
		s.mu.Lock()
		n := len(s.tunnels)
		s.mu.Unlock()
		fmt.Fprintf(w, "tunler server %s on %s, %d active tunnel(s)\n\ninstall the client:\n  curl -fsSL https://%s/install | sh\n", Version, s.cfg.Domain, n, s.cfg.Domain)
	default:
		if name, ok := strings.CutPrefix(r.URL.Path, "/dl/"); ok {
			s.handleDownload(w, r, name)
			return
		}
		http.NotFound(w, r)
	}
}

// serveTunnel proxies a public request through the tunnel for label. It logs
// nothing about the request; tunler keeps no record of proxied traffic.
func (s *Server) serveTunnel(w http.ResponseWriter, r *http.Request, label string) {
	s.mu.Lock()
	t, ok := s.tunnels[label]
	s.mu.Unlock()
	if !ok {
		http.Error(w, fmt.Sprintf("no active tunnel for %q", label), http.StatusBadGateway)
		return
	}

	// Tunnel-level protection: the client may require basic auth from every
	// visitor (tunler connect ... --auth user:pass).
	if t.auth != "" {
		user, pass, has := r.BasicAuth()
		if !has || subtle.ConstantTimeCompare([]byte(user+":"+pass), []byte(t.auth)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="tunler"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
	}

	if n := s.cfg.Limits.MaxBodyBytes; n > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, n)
	}
	r = r.WithContext(context.WithValue(r.Context(), labelKey{}, label))
	s.proxy.ServeHTTP(w, r)
}

// --- user accounts ---

// handleLogin exchanges the master password for a new user secret, creating
// the user on first login. Each login mints an additional secret, so logging
// in from a second machine doesn't invalidate the first.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req protocol.LoginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if wait := s.lockoutRemaining(); wait > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", wait.Seconds()))
		httpError(w, http.StatusTooManyRequests,
			fmt.Sprintf("too many failed logins; retry in %s", wait.Round(time.Second)))
		return
	}

	if subtle.ConstantTimeCompare([]byte(HashPassword(req.Password)), []byte(s.cfg.PasswordHash)) != 1 {
		s.recordLoginFailure(r.RemoteAddr)
		time.Sleep(loginFailDelay)
		httpError(w, http.StatusUnauthorized, "invalid password")
		return
	}
	s.resetLoginFailures()

	if !ValidEmail(req.Email) {
		httpError(w, http.StatusBadRequest, "invalid email address")
		return
	}
	if !s.cfg.Registration.allowsEmail(req.Email) {
		httpError(w, http.StatusForbidden, "email is not permitted to register on this server")
		return
	}
	secret, err := s.state.AddSecret(req.Email)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not store user")
		return
	}
	log.Printf("login: %s from %s", req.Email, r.RemoteAddr)
	writeJSON(w, protocol.LoginResponse{Secret: secret})
}

// lockoutRemaining returns how long logins are locked, or 0 if open.
func (s *Server) lockoutRemaining() time.Duration {
	if !s.cfg.Lockout.Enabled {
		return 0
	}
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	return time.Until(s.loginLock)
}

// recordLoginFailure escalates the global lockout after enough failures.
func (s *Server) recordLoginFailure(remoteAddr string) {
	if !s.cfg.Lockout.Enabled {
		return
	}
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	s.loginFails++
	if over := s.loginFails - s.cfg.Lockout.Threshold; over >= 0 {
		backoff := min(time.Minute<<over, time.Duration(s.cfg.Lockout.MaxBackoff))
		s.loginLock = time.Now().Add(backoff)
		log.Printf("login locked for %s after %d failures (last from %s)", backoff, s.loginFails, remoteAddr)
	}
}

func (s *Server) resetLoginFailures() {
	s.loginMu.Lock()
	s.loginFails = 0
	s.loginMu.Unlock()
}

// handleLogout revokes the presented secret.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	email, ok := s.authUser(w, r)
	if !ok {
		return
	}
	if err := s.state.RevokeSecret(r.Header.Get(protocol.HeaderSecret)); err != nil {
		httpError(w, http.StatusInternalServerError, "could not revoke secret")
		return
	}
	log.Printf("logout: %s", email)
	w.WriteHeader(http.StatusNoContent)
}

// handleDomains lists the authenticated user's claimed domains.
func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	email, ok := s.authUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, protocol.DomainsResponse{Domains: s.state.DomainsOf(email)})
}

// handleRelease unclaims a domain owned by the authenticated user.
func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	email, ok := s.authUser(w, r)
	if !ok {
		return
	}
	var req protocol.ReleaseRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.state.Release(req.Domain, email); err != nil {
		httpError(w, releaseStatus(err), err.Error())
		return
	}
	log.Printf("released domain %q by %s", req.Domain, email)
	s.syncTraefikLogged()
	w.WriteHeader(http.StatusNoContent)
}

func releaseStatus(err error) int {
	switch {
	case errors.Is(err, ErrDomainNotClaimed):
		return http.StatusNotFound
	case errors.Is(err, ErrDomainTaken):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// --- control channel ---

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	domain, email, ok := s.authTunnel(w, r)
	if !ok {
		return
	}

	// First use claims the domain for this user; from then on only their
	// secrets can tunnel on it. The claim is atomic, so cert/Traefik setup
	// keys off a single trustworthy signal.
	newlyClaimed, err := s.state.Claim(domain, email)
	if err != nil {
		httpError(w, http.StatusForbidden, err.Error())
		return
	}
	if newlyClaimed {
		log.Printf("domain %q claimed by %s", domain, email)
		s.syncTraefikLogged()
	}

	s.mu.Lock()
	if _, busy := s.tunnels[domain]; busy {
		s.mu.Unlock()
		httpError(w, http.StatusConflict, "domain already has an active tunnel")
		return
	}
	s.mu.Unlock()

	conn, br, err := hijack(w)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}

	t := &tunnel{
		domain:  domain,
		auth:    r.Header.Get(protocol.HeaderAuth),
		conn:    conn,
		enc:     json.NewEncoder(conn),
		pending: map[string]chan net.Conn{},
	}
	if n := s.cfg.Limits.MaxConnsPerTunnel; n > 0 {
		t.sem = make(chan struct{}, n)
	}

	s.mu.Lock()
	// Re-check under lock; another control request may have won the race.
	if _, busy := s.tunnels[domain]; busy {
		s.mu.Unlock()
		conn.Close()
		return
	}
	s.tunnels[domain] = t
	s.mu.Unlock()

	log.Printf("tunnel up: %s.%s (%s) from %s", domain, s.cfg.Domain, email, conn.RemoteAddr())
	s.runControl(t, br)
	s.removeTunnel(t)
	log.Printf("tunnel down: %s.%s", domain, s.cfg.Domain)
}

// runControl reads keepalives from the client until the connection dies.
func (s *Server) runControl(t *tunnel, br *bufio.Reader) {
	defer t.conn.Close()
	dec := json.NewDecoder(br)
	for {
		t.conn.SetReadDeadline(time.Now().Add(readTimeout))
		var msg protocol.Message
		if err := dec.Decode(&msg); err != nil {
			return
		}
		if msg.Type == protocol.TypePing {
			if err := t.send(protocol.Message{Type: protocol.TypePong}); err != nil {
				return
			}
		}
	}
}

func (s *Server) removeTunnel(t *tunnel) {
	s.mu.Lock()
	if s.tunnels[t.domain] == t {
		delete(s.tunnels, t.domain)
	}
	s.mu.Unlock()

	t.mu.Lock()
	t.closed = true
	for id, ch := range t.pending {
		close(ch)
		delete(t.pending, id)
	}
	t.mu.Unlock()
}

func (t *tunnel) send(msg protocol.Message) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return t.enc.Encode(msg)
}

// acquire takes a data-connection slot, returning a one-shot release func and
// whether a slot was available. With no limit configured it always succeeds.
func (t *tunnel) acquire() (release func(), ok bool) {
	if t.sem == nil {
		return func() {}, true
	}
	select {
	case t.sem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-t.sem }) }, true
	default:
		return nil, false
	}
}

// --- data channel ---

// dialTunnel is the ReverseProxy transport's dialer. addr is "<label>:80". It
// asks the client (via the control channel) to dial back a data connection
// and returns that connection, bounded by the per-tunnel limit and idle
// timeout.
func (s *Server) dialTunnel(ctx context.Context, _, addr string) (net.Conn, error) {
	label, _, err := net.SplitHostPort(addr)
	if err != nil {
		label = addr
	}
	s.mu.Lock()
	t, ok := s.tunnels[label]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no active tunnel for %q", label)
	}

	release, ok := t.acquire()
	if !ok {
		return nil, errors.New("tunnel connection limit reached")
	}
	handed := false // release the slot unless a returned conn takes ownership
	defer func() {
		if !handed {
			release()
		}
	}()

	id, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	ch := make(chan net.Conn) // unbuffered: handoff succeeds only if we're still waiting

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("tunnel closed")
	}
	t.pending[id] = ch
	t.mu.Unlock()

	cleanup := func() {
		t.mu.Lock()
		delete(t.pending, id)
		t.mu.Unlock()
	}

	if err := t.send(protocol.Message{Type: protocol.TypeOpen, ID: id}); err != nil {
		cleanup()
		return nil, fmt.Errorf("tunnel control write failed: %w", err)
	}

	timer := time.NewTimer(dialTimeout)
	defer timer.Stop()
	select {
	case conn, alive := <-ch:
		if !alive {
			return nil, errors.New("tunnel closed while connecting")
		}
		handed = true
		return &dataConn{
			Conn:    conn,
			idle:    time.Duration(s.cfg.Limits.DataConnIdleTimeout),
			release: release,
		}, nil
	case <-ctx.Done():
		cleanup()
		return nil, ctx.Err()
	case <-timer.C:
		cleanup()
		return nil, errors.New("timed out waiting for tunnel client")
	}
}

// handleData receives the client's dial-back for a pending connection ID.
func (s *Server) handleData(w http.ResponseWriter, r *http.Request) {
	domain, _, ok := s.authTunnel(w, r)
	if !ok {
		return
	}
	id := r.Header.Get(protocol.HeaderConnID)

	s.mu.Lock()
	t, ok := s.tunnels[domain]
	s.mu.Unlock()
	if !ok {
		httpError(w, http.StatusBadGateway, "no active tunnel")
		return
	}

	t.mu.Lock()
	ch, ok := t.pending[id]
	delete(t.pending, id)
	t.mu.Unlock()
	if !ok {
		httpError(w, http.StatusBadRequest, "unknown connection id")
		return
	}

	conn, br, err := hijack(w)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	delivered := &bufferedConn{Conn: conn, r: br}
	// The channel is unbuffered: deliver only if dialTunnel is still waiting.
	// Otherwise it gave up (timeout/cancel) and we must not leak the conn.
	select {
	case ch <- delivered:
	default:
		delivered.Close()
	}
}

// dataConn wraps a proxied data connection to enforce an idle deadline and to
// release the tunnel's connection slot exactly once on close.
type dataConn struct {
	net.Conn
	idle    time.Duration
	release func()
	once    sync.Once
}

func (c *dataConn) touch() {
	if c.idle > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
}

func (c *dataConn) Read(p []byte) (int, error)  { c.touch(); return c.Conn.Read(p) }
func (c *dataConn) Write(p []byte) (int, error) { c.touch(); return c.Conn.Write(p) }

func (c *dataConn) Close() error {
	if c.release != nil {
		c.once.Do(c.release)
	}
	return c.Conn.Close()
}

// --- auth helpers ---

// authUser resolves the presented secret to a user email.
func (s *Server) authUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	email, ok := s.state.UserBySecret(r.Header.Get(protocol.HeaderSecret))
	if !ok {
		httpError(w, http.StatusUnauthorized, "invalid or expired secret; run `tunler login`")
		return "", false
	}
	return email, true
}

// authTunnel authenticates a control/data request: valid, non-reserved domain
// label, a valid user secret, and (if the domain is claimed) ownership by
// that user.
func (s *Server) authTunnel(w http.ResponseWriter, r *http.Request) (domain, email string, ok bool) {
	domain = r.Header.Get(protocol.HeaderDomain)
	if !ValidDomain(domain) || s.reserved[domain] {
		httpError(w, http.StatusBadRequest, "invalid or reserved domain")
		return "", "", false
	}
	email, ok = s.authUser(w, r)
	if !ok {
		return "", "", false
	}
	if owner, taken := s.state.Owner(domain); taken && owner != email {
		httpError(w, http.StatusForbidden, "domain is owned by another user")
		return "", "", false
	}
	return domain, email, true
}

// AllowHost is autocert's HostPolicy: issue certificates only for the base
// domain and already-claimed subdomains, so nobody can burn the Let's Encrypt
// rate limit by handshaking random names.
func (s *Server) AllowHost(_ context.Context, host string) error {
	if host == s.cfg.Domain {
		return nil
	}
	if label, ok := strings.CutSuffix(host, "."+s.cfg.Domain); ok && !strings.Contains(label, ".") {
		if _, claimed := s.state.Owner(label); claimed {
			return nil
		}
	}
	return fmt.Errorf("host %q not allowed", host)
}

// downloadAuthorized reports whether a client-download request may proceed.
func (s *Server) downloadAuthorized(r *http.Request) bool {
	if !s.cfg.Downloads.RequireAuth {
		return true
	}
	_, pass, ok := r.BasicAuth()
	return ok && subtle.ConstantTimeCompare([]byte(HashPassword(pass)), []byte(s.cfg.PasswordHash)) == 1
}

func (s *Server) syncTraefikLogged() {
	if err := s.SyncTraefik(); err != nil {
		log.Printf("warning: could not update traefik config: %v", err)
	}
}

// --- low-level helpers ---

// hijack takes over the underlying TCP connection and completes the
// 101 Switching Protocols response by hand.
func hijack(w http.ResponseWriter) (net.Conn, *bufio.Reader, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("connection cannot be hijacked")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	conn.SetDeadline(time.Time{})
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + protocol.UpgradeProto + "\r\nConnection: Upgrade\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, brw.Reader, nil
}

// bufferedConn ensures bytes already buffered by the HTTP server's reader are
// not lost after hijacking.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: msg})
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
