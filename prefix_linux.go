//go:build linux

package lanipv6

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

const ifaFlags = 8 // IFA_FLAGS, the 32-bit address-flags attribute.
var globalUnicast = netip.MustParsePrefix("2000::/3")

func interfacePrefixes() ([]netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	indexes := make(map[int]bool)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			indexes[iface.Index] = true
		}
	}
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_INET6)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil, err
	}
	return prefixesFromMessages(messages, indexes)
}
func prefixesFromMessages(messages []syscall.NetlinkMessage, indexes map[int]bool) ([]netip.Prefix, error) {
	seen := map[netip.Prefix]bool{}
	out := []netip.Prefix{}
	for _, m := range messages {
		if m.Header.Type != syscall.RTM_NEWADDR {
			continue
		}
		if len(m.Data) < syscall.SizeofIfAddrmsg {
			return nil, fmt.Errorf("short address message")
		}
		if m.Data[0] != syscall.AF_INET6 || m.Data[1] != 64 || m.Data[3] != 0 || !indexes[int(binary.NativeEndian.Uint32(m.Data[4:8]))] {
			continue
		}
		flags := uint32(m.Data[2])
		var ip netip.Addr
		preferred := uint32(1)
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return nil, err
		}
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.IFA_ADDRESS, syscall.IFA_LOCAL:
				if len(a.Value) == 16 {
					if v, ok := netip.AddrFromSlice(a.Value); ok {
						ip = v
					}
				}
			case ifaFlags:
				if len(a.Value) < 4 {
					return nil, fmt.Errorf("short address flags")
				}
				flags = binary.NativeEndian.Uint32(a.Value[:4])
			case syscall.IFA_CACHEINFO:
				if len(a.Value) < 4 {
					return nil, fmt.Errorf("short address lifetime")
				}
				preferred = binary.NativeEndian.Uint32(a.Value[:4])
			}
		}
		if flags&(syscall.IFA_F_TEMPORARY|syscall.IFA_F_DEPRECATED|syscall.IFA_F_TENTATIVE|syscall.IFA_F_DADFAILED) != 0 || preferred == 0 || !ip.IsValid() || !ip.IsGlobalUnicast() || !globalUnicast.Contains(ip) {
			continue
		}
		prefix := netip.PrefixFrom(ip, 64).Masked()
		if !seen[prefix] {
			seen[prefix] = true
			out = append(out, prefix)
		}
	}
	return out, nil
}
