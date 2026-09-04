package querylog

import "github.com/AdguardTeam/AdGuardHome/internal/whois"

// Client is the information required by the query log to match against clients
// during searches.
type Client struct {
	WHOIS          *whois.Info `json:"whois,omitempty"`
	Name           string      `json:"name"`
	DisallowedRule string      `json:"disallowed_rule"`
	Disallowed     bool        `json:"disallowed"`
	IgnoreQueryLog bool        `json:"-"`

	// IDs contains the client's identifiers, such as IP addresses and
	// ClientIDs.  It's only set by the clients enumeration used to push the
	// client-name search criteria and the per-client ignore settings down to
	// the database, and it isn't serialized.
	IDs []string `json:"-"`
}

// clientCacheKey is the key by which a cached client information is found.
type clientCacheKey struct {
	clientID string
	ip       string
}

// clientCache is the cache of client information found throughout a request to
// the query log API.  It is used both to speed up the lookup, as well as to
// make sure that changes in client data between two lookups don't create
// discrepancies in our response.
type clientCache map[clientCacheKey]*Client
