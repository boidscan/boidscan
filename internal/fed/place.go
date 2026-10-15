package fed

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/boidscan/boidscan/internal/catalog"
)

// Member is a boid that can hold blocks and take work.
type Member struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

func (m Member) Label() string { return Record{ID: m.ID, Name: m.Name}.Label() }

// View is one boid's idea of the flock: itself plus the peers it cooperates with.
type View struct {
	self     string
	members  map[string]Member
	ids      []string
	replicas int
	table    *homeTable
}

func NewView(self Member, peers []Peer, cat catalog.Catalog, keep func(Peer) bool) View {
	v := View{self: self.ID, members: map[string]Member{self.ID: self}, replicas: cat.Replicas}
	for _, p := range peers {
		if keep(p) {
			v.members[p.ID] = Member{ID: p.ID, Name: p.Name, Endpoint: p.Endpoint}
		}
	}
	for id := range v.members {
		v.ids = append(v.ids, id)
	}
	slices.Sort(v.ids)
	v.table = tableFor(v.ids, v.replicas)
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
	for _, id := range v.homes(block) {
		out = append(out, v.members[id])
	}
	return out
}

func (v View) IsHome(block netip.Prefix, id string) bool {
	return slices.Contains(v.homes(block), id)
}

func (v View) homes(block netip.Prefix) []string {
	if v.table == nil {
		return homes(block, v.ids, v.replicas)
	}
	return v.table.homes(block)
}

// homeTable remembers the homes of each block for one membership. Views are
// rebuilt for every request, but membership rarely changes.
type homeTable struct {
	ids      []string
	replicas int
	mu       sync.RWMutex
	byBlock  map[netip.Prefix][]string
}

const keptTables = 8

var tables struct {
	sync.Mutex
	byKey map[string]*homeTable
	order []string
}

func tableFor(ids []string, replicas int) *homeTable {
	key := strconv.Itoa(replicas) + "\n" + strings.Join(ids, "\n")
	tables.Lock()
	defer tables.Unlock()
	if t, ok := tables.byKey[key]; ok {
		return t
	}
	if tables.byKey == nil {
		tables.byKey = map[string]*homeTable{}
	}
	if len(tables.order) == keptTables {
		delete(tables.byKey, tables.order[0])
		tables.order = tables.order[1:]
	}
	t := &homeTable{ids: slices.Clone(ids), replicas: replicas, byBlock: map[netip.Prefix][]string{}}
	tables.byKey[key] = t
	tables.order = append(tables.order, key)
	return t
}

func (t *homeTable) homes(block netip.Prefix) []string {
	t.mu.RLock()
	h, ok := t.byBlock[block]
	t.mu.RUnlock()
	if ok {
		return h
	}
	h = homes(block, t.ids, t.replicas)
	t.mu.Lock()
	t.byBlock[block] = h
	t.mu.Unlock()
	return h
}

// homes picks the n IDs with the highest rendezvous hash for block
// (https://en.wikipedia.org/wiki/Rendezvous_hashing): every boid ranks them the
// same way, and a joining or leaving boid only moves the blocks it wins or held.
// Ties go to the smaller ID.
func homes(block netip.Prefix, ids []string, n int) []string {
	type ranked struct {
		id    string
		score uint64
	}
	top := make([]ranked, 0, n+1)
	key := []byte(block.String() + "\n")
	base := len(key)
	for _, id := range ids {
		key = append(key[:base], id...)
		h := sha256.Sum256(key)
		r := ranked{id, binary.BigEndian.Uint64(h[:8])}
		i := len(top)
		for i > 0 && (r.score > top[i-1].score || r.score == top[i-1].score && r.id < top[i-1].id) {
			i--
		}
		if i < n {
			top = slices.Insert(top, i, r)
			top = top[:min(len(top), n)]
		}
	}
	out := make([]string, len(top))
	for i, r := range top {
		out[i] = r.id
	}
	return out
}
