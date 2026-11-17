// Package lanipv6 provides a Caddy matcher for active IPv6 interface prefixes.
package lanipv6

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() { caddy.RegisterModule(Matcher{}) }

// Matcher matches a direct peer or resolved client against the active global
// IPv6 /64 prefixes assigned to active interfaces.
type Matcher struct {
	ClientIP bool `json:"client_ip,omitempty"`
	cache    *prefixCache
}

func (Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.matchers.lan_ipv6", New: func() caddy.Module { return new(Matcher) }}
}
func (m *Matcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			if d.Val() != "client" {
				return d.Err("expected optional 'client'")
			}
			m.ClientIP = true
			if d.NextArg() {
				return d.ArgErr()
			}
		}
		if d.NextBlock(0) {
			return d.Err("lan_ipv6 does not accept a block")
		}
	}
	return nil
}
func (m *Matcher) Provision(_ caddy.Context) error {
	m.cache = sharedCache
	return nil
}
func (m Matcher) Match(r *http.Request) bool {
	matched, err := m.MatchWithError(r)
	if err != nil {
		caddyhttp.SetVar(r.Context(), caddyhttp.MatcherErrorVarKey, err)
	}
	return matched
}
func (m Matcher) MatchWithError(r *http.Request) (bool, error) {
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return false, caddyhttp.Error(http.StatusTooEarly, fmt.Errorf("TLS handshake not complete"))
	}
	address := r.RemoteAddr
	if m.ClientIP {
		value, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
		if !ok {
			return false, nil
		}
		address = value
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is6() || ip.Is4In6() {
		return false, nil
	}
	if m.cache == nil {
		return false, nil
	}
	for _, p := range m.cache.get() {
		if p.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// All matcher instances share one short-lived cache, including
// during configuration reloads. A failed read clears the cache rather than
// continuing to trust an old prefix.
type prefixCache struct {
	mu       sync.Mutex
	next     time.Time
	prefixes []netip.Prefix
	read     func() ([]netip.Prefix, error)
}

var sharedCache = &prefixCache{read: interfacePrefixes}

func (c *prefixCache) get() []netip.Prefix {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if !now.Before(c.next) {
		p, err := c.read()
		if err != nil {
			p = nil
		}
		c.prefixes = p
		c.next = now.Add(5 * time.Second)
	}
	return c.prefixes
}

var _ caddy.Provisioner = (*Matcher)(nil)
var _ caddyfile.Unmarshaler = (*Matcher)(nil)
var _ caddyhttp.RequestMatcherWithError = (*Matcher)(nil)
