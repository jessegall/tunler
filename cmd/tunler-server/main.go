// tunler-server (tunlerd) is the public half of tunler.
//
// Production (TLS certificates are obtained automatically from Let's Encrypt):
//
//	tunler-server --domain tunler.example.com --password $TUNLER_PASSWORD
//
// With a config file (flags and env override file values):
//
//	tunler-server --config /etc/tunler/config.json
//
// Local development (plain HTTP on a single port, no certificates):
//
//	tunler-server --domain localhost --password test --no-tls --listen :8080
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/jessegall/tunler/internal/server"
)

// runOptions are process-level settings that aren't part of server.Config.
type runOptions struct {
	httpAddr string
	tlsAddr  string
	listen   string
	noTLS    bool
}

func main() {
	cfg, run, err := loadConfig(os.Args[1:], os.Getenv)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		log.Fatal(err)
	}
	if err := serve(cfg, run); err != nil {
		log.Fatal(err)
	}
}

// loadConfig resolves the server configuration with precedence
// flags > env > config file > defaults. Flags carry plain defaults (not env
// values) so fs.Visit can tell which were actually set.
func loadConfig(args []string, getenv func(string) string) (server.Config, runOptions, error) {
	fs := flag.NewFlagSet("tunler-server", flag.ContinueOnError)
	var (
		configPath = fs.String("config", "", "path to a JSON config file")
		domain     = fs.String("domain", "", "base domain, e.g. tunler.example.com")
		password   = fs.String("password", "", "master password (or env TUNLER_PASSWORD)")
		email      = fs.String("email", "", "contact email for Let's Encrypt (optional)")
		dataDir    = fs.String("data", "", "directory for state and TLS certificates")
		binDir     = fs.String("bin", "", "directory with client binaries for /install and /dl/")
		traefik    = fs.String("traefik-file", "", "Traefik dynamic-config file to regenerate (optional)")
		httpAddr   = fs.String("http", ":80", "HTTP listen address (ACME challenges + redirect)")
		tlsAddr    = fs.String("https", ":443", "HTTPS listen address")
		noTLS      = fs.Bool("no-tls", false, "serve plain HTTP only (for local testing)")
		listen     = fs.String("listen", ":8080", "listen address in --no-tls mode")
	)
	if err := fs.Parse(args); err != nil {
		return server.Config{}, runOptions{}, err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// defaults + config file
	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		return server.Config{}, runOptions{}, fmt.Errorf("loading config: %w", err)
	}

	// env overlays the file
	if v := getenv("TUNLER_DOMAIN"); v != "" {
		cfg.Domain = v
	}
	if v := getenv("TUNLER_EMAIL"); v != "" {
		cfg.Email = v
	}
	plainPassword := getenv("TUNLER_PASSWORD")

	// explicitly-set flags overlay env
	if set["domain"] {
		cfg.Domain = *domain
	}
	if set["email"] {
		cfg.Email = *email
	}
	if set["data"] {
		cfg.DataDir = *dataDir
	}
	if set["bin"] {
		cfg.BinDir = *binDir
	}
	if set["traefik-file"] {
		cfg.TraefikFile = *traefik
	}
	if set["password"] {
		plainPassword = *password
	}

	// derived defaults
	if cfg.DataDir == "" {
		cfg.DataDir = defaultDataDir()
	}
	if cfg.BinDir == "" {
		cfg.BinDir = filepath.Join(cfg.DataDir, "bin")
	}
	// A plaintext password from flag/env is hashed and wins over a file hash.
	if plainPassword != "" {
		if cfg.PasswordHash, err = server.HashPassword(plainPassword); err != nil {
			return server.Config{}, runOptions{}, fmt.Errorf("hashing password: %w", err)
		}
	}

	return cfg, runOptions{httpAddr: *httpAddr, tlsAddr: *tlsAddr, listen: *listen, noTLS: *noTLS}, nil
}

func serve(cfg server.Config, run runOptions) error {
	if cfg.Domain == "" {
		return errors.New(`a base domain is required: pass --domain or set "domain" in the config file`)
	}
	if cfg.PasswordHash == "" {
		return errors.New("a master password is required: pass --password, set TUNLER_PASSWORD, or set password_hash in the config file")
	}

	state, err := server.LoadState(filepath.Join(cfg.DataDir, "state.json"))
	if err != nil {
		return fmt.Errorf("loading state: %w", err)
	}
	srv := server.New(cfg, state)
	if err := srv.SyncTraefik(); err != nil {
		return fmt.Errorf("writing traefik config: %w", err)
	}
	go srv.ExpireAccountsEvery(time.Hour)

	if run.noTLS {
		log.Printf("tunler-server (no TLS) on %s for %s and *.%s", run.listen, cfg.Domain, cfg.Domain)
		return newHTTPServer(run.listen, srv).ListenAndServe()
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, "certs")),
		Email:      cfg.Email,
		HostPolicy: srv.AllowHost,
	}
	// autocert fetches a certificate inside the first TLS handshake to a new
	// subdomain, which can outlast the handshake deadline and fail that
	// visitor. Fetching it as soon as the domain is claimed means the first
	// visitor finds it ready.
	srv.OnClaim = func(host string) {
		if _, err := manager.GetCertificate(certHello(host)); err != nil {
			log.Printf("warning: could not fetch certificate for %s: %v", host, err)
		}
	}

	// Port 80: ACME HTTP-01 challenges, everything else redirected to HTTPS.
	go func() {
		log.Fatal(newHTTPServer(run.httpAddr, manager.HTTPHandler(nil)).ListenAndServe())
	}()

	httpsServer := newHTTPServer(run.tlsAddr, srv)
	httpsServer.TLSConfig = &tls.Config{
		GetCertificate: manager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
	}
	log.Printf("tunler-server on %s for %s and *.%s", run.tlsAddr, cfg.Domain, cfg.Domain)
	return httpsServer.ListenAndServeTLS("", "")
}

// certHello is a ClientHello as a modern browser sends it, so autocert fetches
// the same ECDSA certificate real visitors will be served.
func certHello(host string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:       host,
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: handler,
		// No global read/write timeouts: control channels and streaming
		// responses are long-lived by design. Header reads are bounded and
		// idle keep-alive connections are reaped (hijacked conns unaffected).
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

func defaultDataDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/tunler"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./tunler-data"
	}
	return filepath.Join(home, ".tunler-server")
}
