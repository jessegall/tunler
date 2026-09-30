package server

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/smtp"
	"strconv"
	"sync"
	"time"
)

const (
	codeTTL         = 10 * time.Minute
	codeAttempts    = 5 // wrong codes before a pending login is dropped
	codesPerHour    = 5 // codes mailed per address per hour
	smtpDialTimeout = 15 * time.Second
	smtpTimeout     = 30 * time.Second
)

var (
	errLoginExpired = errors.New("login code expired or unknown; run `tunler login` again")
	errWrongCode    = errors.New("wrong login code")
	errTooManyCodes = errors.New("too many login codes sent to this address; try again later")
)

// mailer sends one plain-text mail. It is an interface so tests can capture
// login codes instead of sending them.
type mailer interface {
	Send(to, subject, body string) error
}

// pendingLogin is a login waiting for its emailed code.
type pendingLogin struct {
	email    string
	code     string
	expires  time.Time
	attempts int
}

// loginCodes tracks pending email-confirmed logins in memory; a restart
// simply drops them and the user logs in again.
type loginCodes struct {
	mu      sync.Mutex
	pending map[string]*pendingLogin // pending ID -> login
	sent    map[string][]time.Time   // email -> when codes were mailed
}

// start mints a code for email, mails it, and returns the pending ID. A
// new code replaces any earlier pending login for the same address.
func (lc *loginCodes) start(m mailer, domain, email string) (string, error) {
	id, err := randomToken(16)
	if err != nil {
		return "", err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	code := fmt.Sprintf("%06d", n.Int64())

	now := time.Now()
	lc.mu.Lock()
	var recent []time.Time
	for _, at := range lc.sent[email] {
		if now.Sub(at) < time.Hour {
			recent = append(recent, at)
		}
	}
	if len(recent) >= codesPerHour {
		lc.sent[email] = recent
		lc.mu.Unlock()
		return "", errTooManyCodes
	}
	lc.sent[email] = append(recent, now)
	for pid, p := range lc.pending {
		if p.email == email || now.After(p.expires) {
			delete(lc.pending, pid)
		}
	}
	lc.pending[id] = &pendingLogin{email: email, code: code, expires: now.Add(codeTTL)}
	lc.mu.Unlock()

	body := fmt.Sprintf("Your tunler login code for %s is:\n\n    %s\n\n"+
		"It expires in %d minutes. If you did not just run `tunler login`, "+
		"someone with the server's master password tried to log in as you; "+
		"without this code they cannot.\n", domain, code, int(codeTTL.Minutes()))
	if err := m.Send(email, "Your tunler login code: "+code, body); err != nil {
		lc.mu.Lock()
		delete(lc.pending, id)
		lc.mu.Unlock()
		return "", err
	}
	return id, nil
}

// finish checks code against the pending login id and returns its email.
func (lc *loginCodes) finish(id, code string) (string, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	p, ok := lc.pending[id]
	if !ok || time.Now().After(p.expires) {
		delete(lc.pending, id)
		return "", errLoginExpired
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(p.code)) != 1 {
		p.attempts++
		if p.attempts >= codeAttempts {
			delete(lc.pending, id)
		}
		return "", errWrongCode
	}
	delete(lc.pending, id)
	return p.email, nil
}

// smtpMailer sends mail through the configured SMTP server. It upgrades to
// TLS with STARTTLS when offered (or uses implicit TLS on port 465), and
// net/smtp refuses to send credentials over an unencrypted connection.
type smtpMailer struct{ cfg SMTP }

func (m smtpMailer) Send(to, subject, body string) error {
	port := m.cfg.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(port))
	tlsCfg := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: smtpDialTimeout}
	var conn net.Conn
	var err error
	if port == 465 {
		conn, err = tls.DialWithDialer(d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(smtpTimeout))
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return err
			}
		}
	}
	if m.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.cfg.From); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := "From: " + m.cfg.From + "\r\nTo: " + to + "\r\nSubject: " + subject +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
