package store

import (
	"context"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/fed"
)

func TestPeers(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	rec := fed.Record{ID: testKey.ID(), Name: "boid-b", Endpoint: "http://192.0.2.5", Time: t0, Signature: []byte("s")}

	if saved, isNew, err := st.SavePeer(ctx, rec); !saved || !isNew || err != nil {
		t.Fatalf("first save = %v, %v, %v", saved, isNew, err)
	}
	if saved, _, err := st.SavePeer(ctx, rec); saved || err != nil {
		t.Fatalf("same record saved again = %v, %v", saved, err)
	}
	if err := st.MarkVerified(ctx, rec.ID, "http://192.0.2.99"); err != nil {
		t.Fatal(err)
	}
	if p := onlyPeer(t, st); p.Verified {
		t.Fatal("verified against a different endpoint")
	}
	st.MarkVerified(ctx, rec.ID, rec.Endpoint)
	st.SetPeerState(ctx, rec.ID, fed.StateAlive)

	rec.Time = t0.Add(time.Second)
	if saved, isNew, _ := st.SavePeer(ctx, rec); !saved || isNew {
		t.Fatalf("newer record: saved=%v isNew=%v", saved, isNew)
	}
	if p := onlyPeer(t, st); !p.Verified || p.State != fed.StateAlive || !p.Time.Equal(rec.Time) {
		t.Fatalf("newer record with the same endpoint must keep verification: %+v", p)
	}

	rec.Time = t0.Add(2 * time.Second)
	rec.Endpoint = "http://192.0.2.6"
	st.SavePeer(ctx, rec)
	if p := onlyPeer(t, st); p.Verified || p.State != fed.StateNew {
		t.Fatalf("a moved endpoint must be verified again: %+v", p)
	}

	if err := st.DeletePeer(ctx, rec.ID); err != nil {
		t.Fatal(err)
	}
	if peers, _ := st.Peers(ctx); len(peers) != 0 {
		t.Fatalf("peers after delete: %+v", peers)
	}
}

func onlyPeer(t *testing.T, st *Store) fed.Peer {
	t.Helper()
	peers, err := st.Peers(context.Background())
	if err != nil || len(peers) != 1 {
		t.Fatalf("Peers = %+v, %v", peers, err)
	}
	return peers[0]
}
