// Package netset holds sets of IP prefixes used for exclusion lists.
package netset

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

type Set struct {
	prefixes []netip.Prefix
}

func (s *Set) Add(p netip.Prefix) {
	s.prefixes = append(s.prefixes, p.Masked())
}

func (s *Set) AddSet(o *Set) {
	s.prefixes = append(s.prefixes, o.prefixes...)
}

func (s *Set) Contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Overlaps reports whether any address of p is in the set.
func (s *Set) Overlaps(p netip.Prefix) bool {
	for _, q := range s.prefixes {
		if q.Overlaps(p) {
			return true
		}
	}
	return false
}

// Covers reports whether every address of p is in a single prefix of the set.
func (s *Set) Covers(p netip.Prefix) bool {
	for _, q := range s.prefixes {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func (s *Set) Prefixes() []netip.Prefix {
	return append([]netip.Prefix(nil), s.prefixes...)
}

func (s *Set) Len() int { return len(s.prefixes) }

// ParsePrefix accepts a CIDR or a bare address.
func ParsePrefix(v string) (netip.Prefix, error) {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// Read parses one CIDR or address per line, ignoring blank lines and # comments.
func Read(r io.Reader) (*Set, error) {
	s := &Set{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		s.Add(p)
	}
	return s, sc.Err()
}

// Write emits the set in the blocklist format read by zmap and zgrab2.
func (s *Set) Write(w io.Writer) error {
	for _, p := range s.prefixes {
		if _, err := fmt.Fprintln(w, p.String()); err != nil {
			return err
		}
	}
	return nil
}
