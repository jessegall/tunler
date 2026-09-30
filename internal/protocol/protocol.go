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

	// LoginPath is a normal JSON POST endpoint that trades a username and
	// password for a user secret, creating the account (which also needs
	// the server master password) when it does not exist yet.
	LoginPath = "/_tunler/login"

	// LogoutPath (POST) revokes the presented secret server-side.
	LogoutPath = "/_tunler/logout"

	// DomainsPath (GET) lists the authenticated user's domains.
	DomainsPath = "/_tunler/domains"

	// ReleasePath (POST) unclaims a domain owned by the authenticated user.
	ReleasePath = "/_tunler/release"

	// VersionPath (GET) reports the server's version, which is also the
	// version of the client binaries it serves.
	VersionPath = "/_tunler/version"

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

// LoginRequest logs in with the account's own password. MasterPassword is
// only needed to create an account; without it, logging in to an unknown
// username fails with CodeMasterPasswordRequired.
type LoginRequest struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	MasterPassword string `json:"master_password,omitempty"`
}

// LoginResponse returns a freshly minted user secret. Every tunnel/domain
// is scoped to the user this secret belongs to.
type LoginResponse struct {
	Secret string `json:"secret"`
}

// DomainsResponse lists the domains owned by the authenticated user.
type DomainsResponse struct {
	Domains []string `json:"domains"`
}

// ReleaseRequest unclaims a domain owned by the authenticated user.
type ReleaseRequest struct {
	Domain string `json:"domain"`
}

// VersionResponse is the answer of VersionPath.
type VersionResponse struct {
	Version string `json:"version"`
}

// ErrorResponse is the JSON body of any non-2xx /_tunler response. Code, when
// set, tells clients what to do next.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// CodeMasterPasswordRequired answers a login for a username that has no
// account yet: send it again with the server master password to create it.
const CodeMasterPasswordRequired = "master_password_required"
