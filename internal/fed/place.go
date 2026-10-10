package fed

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"

	"github.com/boidscan/boidscan/internal/catalog"
)

// Member is a boid that can hold blocks and take work.
type Member struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

func (m Member) Label() string { return Record{ID: m.ID, Name: m.Name}.Label() }

// View is one boid's idea of the flock: itself plus the verified, reachable
// peers with the same catalog.
type View struct {
	self     string
	members  map[string]Member
	ids      []string
	replicas int
}

func NewView(self Member, peers []Peer, cat catalog.Catalog, catalogHash string) View {
	v := View{self: self.ID, members: map[string]Member{self.ID: self}, replicas: cat.Replicas}
	for _, p := range peers {
		if p.Verified && (p.State == StateAlive || p.State == StateSuspect) && p.Catalog == catalogHash {
			v.members[p.ID] = Member{ID: p.ID, Name: p.Name, Endpoint: p.Endpoint}
		}
	}
	for id := range v.members {
		v.ids = append(v.ids, id)
	}
	slices.Sort(v.ids)
	return v
}

// IDs are the sorted member IDs; a change means blocks may have moved.
func (v View) IDs() []string { return v.ids }

func (v View) Has(id string) bool {
	_, ok := v.members[id]
	return ok
}

// Others are the members except this boid.
func (v View) Others() []Member {
	var out []Member
	for _, id := range v.ids {
		if id != v.self {
			out = append(out, v.members[id])
		}
	}
	return out
}

func (v View) Homes(block netip.Prefix) []Member {
	var out []Member
	for _, id := range homes(block, v.ids, v.replicas) {
		out = append(out, v.members[id])
	}
	return out
}

func (v View) IsHome(block netip.Prefix, id string) bool {
	return slices.Contains(homes(block, v.ids, v.replicas), id)
}

// homes picks the n IDs with the highest rendezvous hash for block
// (https://en.wikipedia.org/wiki/Rendezvous_hashing): every boid ranks them the
// same way, and a joining or leaving boid only moves the blocks it wins or held.
func homes(block netip.Prefix, ids []string, n int) []string {
	ranked := slices.Clone(ids)
	slices.SortFunc(ranked, func(a, b string) int {
		if c := cmp.Compare(score(block, b), score(block, a)); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})
	return ranked[:min(n, len(ranked))]
}

func score(block netip.Prefix, id string) uint64 {
	h := sha256.Sum256([]byte(block.String() + "\n" + id))
	return binary.BigEndian.Uint64(h[:8])
}
