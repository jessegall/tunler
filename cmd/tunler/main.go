// tunler exposes a local port on a public subdomain of your tunler server.
//
// Persistent (login once per machine):
//
//	tunler login you@example.com --host=tunler.example.com
//	tunler 8000 --domain=my-app
//
// One-shot / CI (no prompts, no saved state):
//
//	tunler connect 8000 --host=tunler.example.com --domain=my-app --secret=XXX
//	tunler connect 8000 --host=tunler.example.com --domain=my-app --user=you --password=XXX
package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/jessegall/tunler/internal/client"
)

// version is stamped at build time via -ldflags.
var version = "dev"

// usageError is a command misuse; main maps it to exit code 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usageErr(format string, a ...any) error { return &usageError{fmt.Sprintf(format, a...)} }

// errInterrupted is returned when the user aborts a prompt (Ctrl+C).
var errInterrupted = errors.New("interrupted")

// errReported signals "already printed, just exit non-zero".
var errReported = errors.New("")

func main() {
	log.SetFlags(log.Ltime)
	err := run(os.Args[1:])
	switch {
	case err == nil:
		return
	case errors.Is(err, errReported):
		os.Exit(1)
	case errors.Is(err, errInterrupted):
		os.Exit(130)
	default:
		var ue *usageError
		if errors.As(err, &ue) {
			fmt.Fprintln(os.Stderr, ue.msg)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "connect"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") && !isTarget(args[0]) {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "connect":
		return cmdConnect(args)
	case "login":
		return cmdLogin(args)
	case "logout":
		return cmdLogout(args)
	case "domains":
		return cmdDomains(args)
	case "release":
		return cmdRelease(args)
	case "list", "ls":
		return cmdList(args)
	case "disconnect":
		return cmdDisconnect(args)
	case "logs":
		return cmdLogs(args)
	case "status":
		return cmdStatus(args)
	case "update":
		return cmdUpdate(args)
	case "version", "--version", "-v":
		fmt.Printf("tunler %s\n", version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return usageErr("unknown command %q", cmd)
	}
}

// opts are the shared flags; every subcommand accepts all of them so any
// workflow can be expressed as one command.
type opts struct {
	host           string
	domain         string
	secret         string
	user           string
	password       string
	masterPassword string
	auth           string
	logFile        string
	inspect        int
	insecure       bool
	noSave         bool
	detached       bool
	ephemeral      bool
	all            bool
	jsonOut        bool
	follow         bool
	check          bool
}

// parse resolves flags and positionals for a subcommand. Flags and positional
// arguments may be interleaved. Note: "--" is not supported as a separator.
func parse(name string, args []string) (opts, []string, error) {
	var o opts
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&o.host, "host", os.Getenv("TUNLER_HOST"), "tunler server (or env TUNLER_HOST)")
	fs.StringVar(&o.domain, "domain", "", "subdomain to use, e.g. my-app -> my-app.<host>")
	fs.StringVar(&o.secret, "secret", os.Getenv("TUNLER_SECRET"), "user secret (or env TUNLER_SECRET)")
	fs.StringVar(&o.user, "user", "", "username (for inline login)")
	fs.StringVar(&o.user, "email", "", "old name of --user")
	fs.StringVar(&o.password, "password", os.Getenv("TUNLER_PASSWORD"), "account password (or env TUNLER_PASSWORD)")
	fs.StringVar(&o.masterPassword, "master-password", os.Getenv("TUNLER_MASTER_PASSWORD"), "server master password, to create an account (or env TUNLER_MASTER_PASSWORD)")
	fs.StringVar(&o.auth, "auth", os.Getenv("TUNLER_AUTH"), "require basic auth from visitors, e.g. --auth=user:pass")
	fs.IntVar(&o.inspect, "inspect", 4646, "local web inspector port (0 to disable)")
	fs.BoolVar(&o.insecure, "insecure", false, "connect over plain HTTP (local testing only)")
	fs.BoolVar(&o.noSave, "no-save", false, "do not persist credentials to the config file")
	fs.BoolVar(&o.detached, "detached", false, "run the tunnel in the background")
	fs.BoolVar(&o.detached, "d", false, "shorthand for --detached")
	fs.BoolVar(&o.ephemeral, "ephemeral", false, "release the domain when the tunnel exits")
	fs.StringVar(&o.logFile, "log-file", "", "internal: log path of this background tunnel")
	fs.BoolVar(&o.all, "all", false, "apply to all (disconnect/release)")
	fs.BoolVar(&o.jsonOut, "json", false, "machine-readable JSON output")
	fs.BoolVar(&o.follow, "follow", false, "keep following log output (logs)")
	fs.BoolVar(&o.follow, "f", false, "shorthand for --follow")
	fs.BoolVar(&o.check, "check", false, "only report whether an update is available (update)")

	var positional []string
	for rest := args; len(rest) > 0; {
		if err := fs.Parse(rest); err != nil {
			return o, nil, &usageError{err.Error()}
		}
		rest = fs.Args()
		if len(rest) > 0 {
			positional = append(positional, rest[0])
			rest = rest[1:]
		}
	}
	return o, positional, nil
}

// resolveHost auto-fills the host when the flag is omitted: saved login first,
// then the server the client was installed from.
func resolveHost(flagHost string, store client.Store) string {
	if flagHost != "" {
		return flagHost
	}
	if store.DefaultHost != "" {
		return store.DefaultHost
	}
	return client.InstalledHost()
}

// creds resolves host and secret: flags/env first, then the saved login,
// performing an inline login if a username was supplied.
func (o *opts) creds(needSecret bool) (client.Config, client.Store, error) {
	store := client.LoadStore()
	o.host = resolveHost(o.host, store)
	if o.host == "" {
		return client.Config{}, store, usageErr("no server given: pass --host=... (or run `tunler login <username> --host=...` once)")
	}
	cfg := client.Config{Host: o.host, Domain: o.domain, Secret: o.secret, Insecure: o.insecure}

	if cfg.Secret == "" {
		if saved, ok := store.Hosts[o.host]; ok {
			cfg.Secret = saved.Secret
			if o.user == "" {
				o.user = saved.User
			}
		}
	}

	if cfg.Secret == "" && o.user != "" {
		secret, err := o.login(cfg)
		if err != nil {
			return cfg, store, fmt.Errorf("login failed: %w", err)
		}
		cfg.Secret = secret
		if !o.noSave {
			saved := store.Hosts[o.host]
			saved.User, saved.Secret = o.user, secret
			store.Hosts[o.host] = saved
			if store.DefaultHost == "" {
				store.DefaultHost = o.host
			}
			if err := store.Save(); err != nil {
				log.Printf("warning: could not save credentials: %v", err)
			}
		}
	}

	if needSecret && cfg.Secret == "" {
		return cfg, store, usageErr("not logged in to %s: run `tunler login <username> --host=%s`, or pass --secret=... / --user=... --password=... directly", o.host, o.host)
	}
	return cfg, store, nil
}

// --- connect ---

func cmdConnect(args []string) error {
	o, positional, err := parse("connect", args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErr("usage: tunler connect <port|host:port> [--domain=<name>]")
	}
	cfg, store, err := o.creds(true)
	if err != nil {
		return err
	}
	if o.domain == "" {
		// No domain requested: use a random ephemeral one, released on exit.
		if o.domain, err = pickEphemeral(&store, cfg.Host, !o.noSave); err != nil {
			return err
		}
		o.ephemeral = true
	}
	cfg.Target = normalizeTarget(positional[0])
	cfg.Domain = o.domain
	cfg.Auth = o.auth

	if o.detached {
		return spawnDetached(o, cfg, store)
	}

	// The tunnel process owns its pidfile so `tunler list` sees it; a
	// --log-file (set by the --detached parent) marks it as a background
	// tunnel. Cleanup runs on Ctrl+C / SIGTERM (what `tunler disconnect` sends).
	mode := "foreground"
	if o.logFile != "" {
		mode = "background"
	}
	info := tunnelInfo{
		Domain: cfg.Domain, Host: cfg.Host, Target: cfg.Target,
		URL: cfg.URL(), PID: os.Getpid(), Mode: mode, Log: o.logFile,
		Started: time.Now(),
	}
	writeInfo(info)
	unlock := holdTunnelLock(cfg.Host, cfg.Domain)
	cleanup := func() {
		unlock()
		removeInfo(cfg.Host, cfg.Domain)
		if o.ephemeral {
			client.Release(cfg, cfg.Domain)
		}
	}
	// A background child marks its pidfile ready once up, so its parent knows
	// startup succeeded without scraping log output.
	everUp := false
	onUp := func() {
		everUp = true
		if o.logFile != "" {
			info.Ready = true
			writeInfo(info)
		}
	}
	if o.ephemeral {
		log.Printf("using ephemeral domain %q (released on exit)", cfg.Domain)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cleanup()
		os.Exit(0)
	}()

	var ins *client.Inspector
	if o.inspect > 0 {
		ins = client.NewInspector()
		if addr, err := ins.Serve(o.inspect); err == nil {
			log.Printf("inspector: %s", addr)
		} else {
			log.Printf("inspector disabled: %v", err)
		}
	}

	backoff := time.Second
	repicks := 0
	for {
		start := time.Now()
		err := client.Run(cfg, ins, onUp)

		var authErr *client.AuthError
		taken := errors.As(err, &authErr) && authErr.Status == http.StatusForbidden
		// A remembered random name may since belong to another user, or be
		// live on another of this user's machines: move to a fresh name, but
		// only before the tunnel was ever up, so a working URL never changes.
		if o.ephemeral && !everUp && o.logFile == "" && repicks < 5 && (taken || errors.Is(err, client.ErrBusy)) {
			repicks++
			if taken {
				forgetEphemeral(&store, cfg.Host, cfg.Domain, !o.noSave)
			}
			next, perr := newEphemeral(&store, cfg.Host, !o.noSave)
			if perr != nil {
				return perr
			}
			unlock()
			removeInfo(cfg.Host, cfg.Domain)
			cfg.Domain = next
			info.Domain, info.URL = next, cfg.URL()
			writeInfo(info)
			unlock = holdTunnelLock(cfg.Host, cfg.Domain)
			log.Printf("%v; using ephemeral domain %q instead", err, next)
			continue
		}
		if authErr != nil {
			cleanup()
			if authErr.Status == http.StatusUnauthorized {
				return fmt.Errorf("rejected by server: %v\n(hint: `tunler login <username> --host=%s` to refresh credentials)", authErr, cfg.Host)
			}
			return fmt.Errorf("rejected by server: %v", authErr)
		}

		if time.Since(start) > time.Minute {
			backoff = time.Second // connection was healthy; reset backoff
		}
		log.Printf("%v; reconnecting in %s", err, backoff)
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// maxEphemeral bounds how many random domains are remembered per server.
const maxEphemeral = 8

// pickEphemeral returns a domain for a tunnel started without --domain. Every
// new name makes the server fetch a new TLS certificate, and Let's Encrypt
// allows only 50 a week per registered domain, so names are remembered per
// server and reused once no tunnel on this machine holds them.
func pickEphemeral(store *client.Store, host string, save bool) (string, error) {
	inUse := map[string]bool{}
	for _, t := range readTunnels() {
		if t.Host == host {
			inUse[t.Domain] = true
		}
	}
	for _, d := range store.Hosts[host].Ephemeral {
		if !inUse[d] {
			return d, nil
		}
	}
	return newEphemeral(store, host, save)
}

// newEphemeral mints a random domain and remembers it for host.
func newEphemeral(store *client.Store, host string, save bool) (string, error) {
	d, err := randomDomain()
	if err != nil {
		return "", err
	}
	creds := store.Hosts[host]
	creds.Ephemeral = append(creds.Ephemeral, d)
	if n := len(creds.Ephemeral); n > maxEphemeral {
		creds.Ephemeral = creds.Ephemeral[n-maxEphemeral:]
	}
	store.Hosts[host] = creds
	if save {
		if err := store.Save(); err != nil {
			log.Printf("warning: could not remember ephemeral domain: %v", err)
		}
	}
	return d, nil
}

// forgetEphemeral drops a remembered domain that another user now owns.
func forgetEphemeral(store *client.Store, host, domain string, save bool) {
	creds := store.Hosts[host]
	kept := creds.Ephemeral[:0]
	for _, d := range creds.Ephemeral {
		if d != domain {
			kept = append(kept, d)
		}
	}
	creds.Ephemeral = kept
	store.Hosts[host] = creds
	if save {
		store.Save()
	}
}

// randomDomain generates a memorable ephemeral subdomain like "brave-otter-42".
// The 16-entry lists divide 256 evenly, so byte-modulo indexing is unbiased.
func randomDomain() (string, error) {
	adjectives := []string{"brave", "calm", "eager", "fuzzy", "gentle", "happy",
		"jolly", "lucky", "mellow", "nimble", "proud", "quick", "shiny", "sunny",
		"swift", "witty"}
	nouns := []string{"otter", "falcon", "badger", "lynx", "heron", "mole",
		"raven", "stoat", "tapir", "vole", "wren", "yak", "ibex", "koala",
		"marmot", "newt"}
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s-%d", adjectives[int(b[0])%len(adjectives)], nouns[int(b[1])%len(nouns)], int(b[2])%100), nil
}

func cmdStatus(args []string) error {
	o, _, err := parse("status", args)
	if err != nil {
		return err
	}
	store := client.LoadStore()
	host := resolveHost(o.host, store)

	type status struct {
		Host     string `json:"host,omitempty"`
		User     string `json:"user,omitempty"`
		Email    string `json:"email,omitempty"` // old name of user, kept for scripts
		LoggedIn bool   `json:"logged_in"`
		AuthOK   bool   `json:"auth_ok"`
		Tunnels  int    `json:"tunnels"`
	}
	st := status{Host: host, Tunnels: len(readTunnels())}
	if creds, ok := store.Hosts[host]; ok && host != "" {
		st.User, st.Email = creds.User, creds.User
		st.LoggedIn = true
		cfg := client.Config{Host: host, Secret: creds.Secret, Insecure: o.insecure}
		if o.secret != "" {
			cfg.Secret = o.secret
		}
		_, err := client.Domains(cfg)
		st.AuthOK = err == nil
	}

	switch {
	case o.jsonOut:
		json.NewEncoder(os.Stdout).Encode(st)
	case !st.LoggedIn:
		fmt.Fprintf(os.Stderr, "not logged in (host: %q); run: tunler login <username> --host=<server>\n", host)
	default:
		okStr := "ok"
		if !st.AuthOK {
			okStr = "FAILED, run tunler login again"
		}
		fmt.Printf("host:    %s\nuser:    %s\nauth:    %s\ntunnels: %d running (tunler list)\n",
			st.Host, st.User, okStr, st.Tunnels)
	}
	if !st.LoggedIn || !st.AuthOK {
		return errReported
	}
	return nil
}

// --- login / logout ---

func cmdLogin(args []string) error {
	o, positional, err := parse("login", args)
	if err != nil {
		return err
	}
	if len(positional) == 1 && o.user == "" {
		o.user = positional[0]
	} else if len(positional) > 0 {
		return usageErr("usage: tunler login <username> [--host=<server>] [--password=...|--secret=...]")
	}
	if o.user == "" {
		return usageErr("usage: tunler login <username> [--host=<server>] [--password=...|--secret=...]")
	}
	o.host = resolveHost(o.host, client.LoadStore())
	if o.host == "" {
		return usageErr("no server given: tunler login <username> --host=tunler.example.com")
	}

	cfg := client.Config{Host: o.host, Insecure: o.insecure}
	secret, err := o.login(cfg)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	if o.noSave {
		// Stateless mode: hand the secret to the caller instead of saving.
		fmt.Println(secret)
		return nil
	}
	store := client.LoadStore()
	saved := store.Hosts[o.host]
	saved.User, saved.Secret = o.user, secret
	store.Hosts[o.host] = saved
	store.DefaultHost = o.host
	if err := store.Save(); err != nil {
		return fmt.Errorf("could not save credentials: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Logged in to %s as %s (saved; %s is now the default host).\n", o.host, o.user, o.host)
	return nil
}

func cmdLogout(args []string) error {
	o, _, err := parse("logout", args)
	if err != nil {
		return err
	}
	cfg, store, err := o.creds(false)
	if err != nil {
		return err
	}
	if cfg.Secret == "" {
		return fmt.Errorf("not logged in to %s", o.host)
	}
	if err := client.Logout(cfg); err != nil {
		log.Printf("warning: server-side revoke failed: %v", err)
	}
	delete(store.Hosts, o.host)
	if store.DefaultHost == o.host {
		store.DefaultHost = ""
	}
	if err := store.Save(); err != nil {
		return fmt.Errorf("could not update config file: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Logged out of %s.\n", o.host)
	return nil
}

// --- domains / release ---

func cmdDomains(args []string) error {
	o, _, err := parse("domains", args)
	if err != nil {
		return err
	}
	cfg, _, err := o.creds(true)
	if err != nil {
		return err
	}
	domains, err := client.Domains(cfg)
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "no domains claimed yet")
		return nil
	}
	for _, d := range domains {
		fmt.Printf("%s.%s\n", d, stripPortHost(cfg.Host))
	}
	return nil
}

func cmdRelease(args []string) error {
	o, positional, err := parse("release", args)
	if err != nil {
		return err
	}
	if o.domain == "" && len(positional) == 1 {
		o.domain = positional[0]
	}
	if o.domain == "" && !o.all {
		return usageErr("usage: tunler release <domain> (or --all)")
	}
	cfg, _, err := o.creds(true)
	if err != nil {
		return err
	}

	domains := []string{o.domain}
	if o.all {
		if domains, err = client.Domains(cfg); err != nil {
			return err
		}
		if len(domains) == 0 {
			fmt.Fprintln(os.Stderr, "no domains to release")
			return nil
		}
	}
	for _, d := range domains {
		if err := client.Release(cfg, d); err != nil {
			fmt.Fprintf(os.Stderr, "could not release %s: %v\n", d, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "Released %s.%s.\n", d, stripPortHost(cfg.Host))
	}
	return nil
}

// --- helpers ---

// login logs in as o.user, prompting for the account password and, when the
// account has to be created first, for the server master password.
func (o *opts) login(cfg client.Config) (string, error) {
	pw := o.password
	if pw == "" {
		var err error
		if pw, err = promptPassword(fmt.Sprintf("Password for %s on %s: ", o.user, o.host), "--password"); err != nil {
			return "", err
		}
	}
	return client.Login(cfg, o.user, pw, func() (string, error) {
		if o.masterPassword != "" {
			return o.masterPassword, nil
		}
		fmt.Fprintf(os.Stderr, "There is no account %q on %s yet; creating it needs the server's master password.\n", o.user, o.host)
		return promptPassword(fmt.Sprintf("Master password for %s: ", o.host), "--master-password")
	})
}

// promptPassword reads a password without echo. It reads the terminal in raw
// mode byte by byte because raw mode disables signal handling, so Ctrl+C must be
// recognized by hand or the prompt cannot be exited.
func promptPassword(prompt, flag string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("password required: pass %s=... when not interactive", flag)
	}
	fmt.Fprint(os.Stderr, prompt)

	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", fmt.Errorf("cannot read password: %w", err)
	}
	defer term.Restore(fd, state)

	var pw []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			break
		}
		switch buf[0] {
		case 3, 4: // Ctrl+C, Ctrl+D
			fmt.Fprintln(os.Stderr, "^C")
			return "", errInterrupted
		case '\r', '\n':
			fmt.Fprintln(os.Stderr)
			return string(pw), nil
		case 127, 8: // backspace
			if len(pw) > 0 {
				pw = pw[:len(pw)-1]
			}
		default:
			pw = append(pw, buf[0])
		}
	}
	fmt.Fprintln(os.Stderr)
	return string(pw), nil
}

// isTarget reports whether s looks like a connect target ("8000",
// "localhost:3000"), which makes bare `tunler 8000 ...` work.
func isTarget(s string) bool {
	if _, err := strconv.Atoi(s); err == nil {
		return true
	}
	return strings.Contains(s, ":")
}

func normalizeTarget(s string) string {
	if _, err := strconv.Atoi(s); err == nil {
		return "127.0.0.1:" + s
	}
	return s
}

func stripPortHost(host string) string {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		return host[:i]
	}
	return host
}

func usage() {
	fmt.Fprintf(os.Stderr, `tunler %s: expose a local port on a public subdomain

USAGE
  tunler login <username> --host=<server>                  log in (first time: creates the account)
  tunler connect <port|host:port> [--domain=<name>]       start a tunnel (or just: tunler 8000)
  tunler list                                             list running tunnels
  tunler disconnect [<domain>|--all]                      stop background tunnel(s)
  tunler logs <domain> [-f]                               show a background tunnel's output
  tunler status                                           where am I logged in, does auth work
  tunler domains                                          list domains you own
  tunler release <domain>|--all                           unclaim domain(s)
  tunler logout                                           forget saved login (and revoke it)
  tunler update [--check] [--json]                        self-update from the server
                                                          (--check: only report)
  tunler version                                          print version

EXAMPLES
  tunler 8000 --domain=my-app          stable https://my-app.<host>
  tunler 8000                          random ephemeral subdomain, released on exit
  tunler 8000 --domain=my-app -d       run in the background
  tunler 8000 --auth=user:pass         visitors must pass basic auth
  tunler connect 8000 --host=tunler.example.com --domain=x --secret=XXX
                                       one-shot, no prompts, no saved state (CI)

FLAGS (all commands; flags/env always override the saved config)
  --host=      tunler server (env TUNLER_HOST)
  --domain=    subdomain to use (omit for a random ephemeral one)
  --secret=    user secret (env TUNLER_SECRET)
  --user=      username, for (inline) login
  --password=  account password (env TUNLER_PASSWORD)
  --master-password=
               server master password, only to create an account or
               download from a gated server (env TUNLER_MASTER_PASSWORD)
  --auth=      user:pass required from visitors of the tunnel
  --inspect=   local web inspector port (default 4646, 0 = off)
  -d           run tunnel in the background (--detached)
  --json       machine-readable output (list, status)
  --no-save    don't write credentials to disk (login prints the secret)
  --insecure   plain HTTP to the server (local testing)

A live request log is printed for foreground tunnels; open the inspector
URL shown at startup to browse full request/response details.
`, version)
}
