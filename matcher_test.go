package lanipv6

import (
	"crypto/tls"
	"errors"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestMatchesOnlyActiveLANPrefix(t *testing.T) {
	calls := 0
	c := &prefixCache{read: func() ([]netip.Prefix, error) {
		calls++
		return []netip.Prefix{netip.MustParsePrefix("2600:1700:1151:d83f::/64")}, nil
	}}
	m := Matcher{cache: c}
	r := httptest.NewRequest("GET", "https://example.test", nil)
	r.TLS = nil
	r.RemoteAddr = "[2600:1700:1151:d83f::123]:1234"
	if !m.Match(r) {
		t.Fatal("local prefix did not match")
	}
	r.RemoteAddr = "[2600:1700:1151:d840::123]:1234"
	if m.Match(r) {
		t.Fatal("unrelated prefix matched")
	}
	if calls != 1 {
		t.Fatalf("cache fetched %d times", calls)
	}
	r.RemoteAddr = "[2600:1700:1151:d83f::123]:1234"
	r.TLS = &tls.ConnectionState{}
	if _, err := m.MatchWithError(r); err == nil {
		t.Fatal("unverified early data must not bypass auth")
	}
}
func TestPrefixReadFailureClearsOldTrust(t *testing.T) {
	c := &prefixCache{prefixes: []netip.Prefix{netip.MustParsePrefix("2600:1700:1151:d83f::/64")}, next: time.Now().Add(-time.Second), read: func() ([]netip.Prefix, error) { return nil, errors.New("interface unavailable") }}
	if got := c.get(); len(got) != 0 {
		t.Fatalf("stale trust retained: %v", got)
	}
}
