// Package protocol defines the wire protocol shared by the tunler client
// and server. Everything runs over a single HTTPS port: the client makes
// plain HTTP requests to reserved /_tunler/* paths and upgrades the
// connection (like WebSocket does) for the control and data channels.
package protocol

const (
	// ControlPath is the endpoint the client upgrades to keep a persistent
	// control connection. The server sends Open messages on it whenever a
	// public visitor connects to the tunnel's subdomain.
	ControlPath = "/_tunler/control"

	// DataPath is the endpoint the client upgrades once per proxied
	// connection, in response to an Open message.
	DataPath = "/_tunler/data"

	// LoginPath is a normal JSON POST endpoint used to create/authenticate a
	// user with the server master password in exchange for a user secret.
	LoginPath = "/_tunler/login"

	// LoginVerifyPath (POST) finishes a login the server confirms by email:
	// it trades the pending ID and the emailed code for the user secret.
	LoginVerifyPath = "/_tunler/login/verify"

	// LogoutPath (POST) revokes the presented secret server-side.
	LogoutPath = "/_tunler/logout"

	// DomainsPath (GET) lists the authenticated user's domains.
	DomainsPath = "/_tunler/domains"

	// ReleasePath (POST) unclaims a domain owned by the authenticated user.
	ReleasePath = "/_tunler/release"

	HeaderDomain = "X-Tunler-Domain"
	HeaderSecret = "X-Tunler-Secret"
	HeaderConnID = "X-Tunler-Conn"

	// HeaderAuth optionally carries "user:pass" on the control handshake;
	// the server then requires HTTP basic auth from visitors of this tunnel.
	HeaderAuth = "X-Tunler-Auth"

	// UpgradeProto is the value of the Upgrade header for tunler channels.
	UpgradeProto = "tunler"
)

// Message types exchanged on the control channel (newline-delimited JSON).
const (
	TypeOpen = "open" // server -> client: dial a data connection for ID
	TypePing = "ping" // either direction: keepalive
	TypePong = "pong" // reply to ping

	// TypeClose (server -> client) ends the tunnel for good, e.g. because its
	// domain was released; the client must not reconnect.
	TypeClose = "close"
)

// Message is a control-channel frame.
type Message struct {
	Type   string `json:"type"`
	ID     string `json:"id,omitempty"`
	Reason string `json:"reason,omitempty"` // TypeClose only
}

// LoginRequest creates (or re-authenticates) a user with the master password.
// Verify declares that the client can finish an email-confirmed login; a
// server that confirms logins by email refuses clients that cannot.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Verify   bool   `json:"verify,omitempty"`
}

// LoginResponse returns a freshly minted user secret. Every tunnel/domain
// is scoped to the user this secret belongs to. When the server confirms
// logins by email it answers 202 with Pending set instead, and the secret
// comes from LoginVerifyPath once the emailed code is presented.
type LoginResponse struct {
	Secret  string `json:"secret,omitempty"`
	Pending string `json:"pending,omitempty"`
}

// LoginVerifyRequest presents the code emailed for a pending login.
type LoginVerifyRequest struct {
	Pending string `json:"pending"`
	Code    string `json:"code"`
}

// DomainsResponse lists the domains owned by the authenticated user.
type DomainsResponse struct {
	Domains []string `json:"domains"`
}

// ReleaseRequest unclaims a domain owned by the authenticated user.
type ReleaseRequest struct {
	Domain string `json:"domain"`
}

// ErrorResponse is the JSON body of any non-2xx /_tunler response.
type ErrorResponse struct {
	Error string `json:"error"`
}
