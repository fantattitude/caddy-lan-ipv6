//go:build linux

package lanipv6

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
)

func addressMessage(ip string, index uint32, flags uint32, preferred uint32) syscall.NetlinkMessage {
	d := make([]byte, 8)
	d[0] = syscall.AF_INET6
	d[1] = 64
	binary.NativeEndian.PutUint32(d[4:8], index)
	attr := func(kind uint16, value []byte) {
		l := 4 + len(value)
		p := make([]byte, (l+3)&^3)
		binary.NativeEndian.PutUint16(p[:2], uint16(l))
		binary.NativeEndian.PutUint16(p[2:4], kind)
		copy(p[4:], value)
		d = append(d, p...)
	}
	v := netip.MustParseAddr(ip).As16()
	attr(syscall.IFA_ADDRESS, v[:])
	f := make([]byte, 4)
	binary.NativeEndian.PutUint32(f, flags)
	attr(ifaFlags, f)
	life := make([]byte, 16)
	binary.NativeEndian.PutUint32(life, preferred)
	attr(syscall.IFA_CACHEINFO, life)
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWADDR}, Data: d}
}
func TestNetlinkFiltersAddresses(t *testing.T) {
	msgs := []syscall.NetlinkMessage{addressMessage("2600:1700:1151:d83f::1", 3, 0, 100), addressMessage("2600:1700:1151:d83f::2", 3, syscall.IFA_F_TEMPORARY, 100), addressMessage("2600:1700:1151:d840::1", 3, syscall.IFA_F_DEPRECATED, 100), addressMessage("2600:1700:1151:d841::1", 3, syscall.IFA_F_TENTATIVE, 100), addressMessage("2600:1700:1151:d842::1", 3, 0, 0), addressMessage("2600:1700:1151:d843::1", 4, 0, 100), addressMessage("fd40:ed4:1107:1::1", 3, 0, 100)}
	p, err := prefixesFromMessages(msgs, map[int]bool{3: true, 4: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 2 || p[0].String() != "2600:1700:1151:d83f::/64" || p[1].String() != "2600:1700:1151:d843::/64" {
		t.Fatalf("unexpected prefixes: %v", p)
	}
	p, err = prefixesFromMessages(msgs, map[int]bool{3: true})
	if err != nil || len(p) != 1 || p[0].String() != "2600:1700:1151:d83f::/64" {
		t.Fatalf("inactive interface was not excluded: %v, %v", p, err)
	}
}
