//go:build !linux

package lanipv6

import (
	"fmt"
	"net/netip"
)

func interfacePrefixes() ([]netip.Prefix, error) {
	return nil, fmt.Errorf("lan_ipv6 requires Linux")
}
