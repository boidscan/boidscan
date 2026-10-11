// Package catalog defines the work every boid in a flock agrees on: how the
// address space is cut into blocks, how many boids hold each block, and which
// ports and handshake modules a scan uses. Boids only cooperate with peers
// whose catalog has the same hash.
package catalog

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/boidscan/boidscan/internal/grab"
	"github.com/boidscan/boidscan/internal/netset"
)

type Catalog struct {
	Name      string
	BlockBits int
	// Replicas is how many boids hold each block.
	Replicas int
	Universe []netip.Prefix
	// Groups are scanned in order: group 0 first in every block, then group 1.
	Groups [][]uint16
}

// Unit is the only kind of work boids hand each other: one block, one port group.
type Unit struct {
	Block netip.Prefix `json:"block"`
	Group int          `json:"group"`
}

func (u Unit) String() string { return u.Block.String() + " group " + strconv.Itoa(u.Group) }

const groupSize = 256

// Default sweeps all of IPv4 in /16 blocks. Group 0 holds the ports with a
// protocol-specific module; the rest of Shodan's list follows in its order.
func Default() Catalog {
	known := map[uint16]bool{}
	var first []uint16
	for _, s := range grab.KnownServices("") {
		known[s.Port] = true
		first = append(first, s.Port)
	}
	slices.Sort(first)
	groups := [][]uint16{first}
	var rest []uint16
	for _, p := range grab.DefaultPorts() {
		if !known[p] {
			rest = append(rest, p)
		}
	}
	for len(rest) > 0 {
		n := min(groupSize, len(rest))
		groups = append(groups, rest[:n])
		rest = rest[n:]
	}
	return Catalog{
		Name:      "internet",
		BlockBits: 16,
		Replicas:  3,
		Universe:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Groups:    groups,
	}
}

// Lab covers a small private range in /30 blocks held by three boids, so a
// five-boid lab has blocks that some boids do not hold, and every result has
// two homes besides its scanner to check it.
func Lab(universe netip.Prefix) (Catalog, error) {
	c := Catalog{
		Name:      "lab",
		BlockBits: 30,
		Replicas:  3,
		Universe:  []netip.Prefix{universe.Masked()},
		Groups:    [][]uint16{{22, 80, 443, 6379}, {2200, 9443}},
	}
	if !universe.Addr().Is4() || universe.Bits() > c.BlockBits || universe.Bits() < 16 {
		return c, fmt.Errorf("lab range %s: want an IPv4 prefix between /16 and /%d", universe, c.BlockBits)
	}
	return c, nil
}

// Hash identifies the catalog, including the module configuration.
func (c Catalog) Hash() string {
	var b strings.Builder
	fmt.Fprintf(&b, "boidscan-catalog-v1\n%s\n%d\n%d\n", c.Name, c.BlockBits, c.Replicas)
	for _, u := range c.Universe {
		fmt.Fprintf(&b, "universe %s\n", u)
	}
	for i, g := range c.Groups {
		ports := make([]string, len(g))
		for j, p := range g {
			ports[j] = strconv.Itoa(int(p))
		}
		fmt.Fprintf(&b, "group %d %s\n", i, strings.Join(ports, ","))
	}
	b.WriteString(grab.INI(append(grab.KnownServices(""), grab.GenericServices("")...)))
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func (c Catalog) Block(ip netip.Addr) netip.Prefix {
	p, _ := ip.Unmap().Prefix(c.BlockBits)
	return p
}

func (c Catalog) Ports(group int) []uint16 { return c.Groups[group] }

// Valid reports whether u is a unit of this catalog.
func (c Catalog) Valid(u Unit) bool {
	if u.Group < 0 || u.Group >= len(c.Groups) || u.Block.Bits() != c.BlockBits || u.Block != u.Block.Masked() {
		return false
	}
	return c.Contains(u.Block.Addr())
}

func (c Catalog) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range c.Universe {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Blocks lists the universe in blocks, leaving out blocks that skip covers entirely.
func (c Catalog) Blocks(skip *netset.Set) []netip.Prefix {
	var out []netip.Prefix
	for _, u := range c.Universe {
		a := u.Addr().As4()
		start := binary.BigEndian.Uint32(a[:])
		step := uint64(1) << (32 - c.BlockBits)
		count := uint64(1) << (c.BlockBits - u.Bits())
		for i := range count {
			binary.BigEndian.PutUint32(a[:], start+uint32(i*step))
			b := netip.PrefixFrom(netip.AddrFrom4(a), c.BlockBits)
			if skip == nil || !skip.Covers(b) {
				out = append(out, b)
			}
		}
	}
	return out
}
