package netset

import (
	"net/netip"
	"strings"
)

// https://www.iana.org/assignments/iana-ipv4-special-registry/
const rfc1918 = `
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
`

const reservedOther = `
0.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
192.0.0.0/24
192.0.2.0/24
192.88.99.0/24
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
255.255.255.255/32
`

// Reserved returns the IANA special-purpose IPv4 ranges. With allowPrivate the
// RFC 1918 ranges are left out so a lab network can be scanned.
func Reserved(allowPrivate bool) *Set {
	src := reservedOther
	if !allowPrivate {
		src += rfc1918
	}
	s, err := Read(strings.NewReader(src))
	if err != nil {
		panic(err)
	}
	return s
}

func IsPrivate(p netip.Prefix) bool {
	s, _ := Read(strings.NewReader(rfc1918))
	for _, q := range s.prefixes {
		if q.Contains(p.Addr()) && q.Bits() <= p.Bits() {
			return true
		}
	}
	return false
}
