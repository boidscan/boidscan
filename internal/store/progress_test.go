package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/pkg/client"
	"github.com/boidscan/boidscan/pkg/sig"
)

func TestProgress(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	other, _ := identity.Generate()
	now := time.Now()

	newer := fed.SignedProgress{Progress: json.RawMessage(`{"n":2}`), Signature: []byte("b")}
	if err := st.SaveProgress(ctx, other.ID(), now, newer); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveProgress(ctx, other.ID(), now.Add(-time.Minute), fed.SignedProgress{Progress: json.RawMessage(`{"n":1}`), Signature: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	all, err := st.Progress(ctx)
	if err != nil || len(all) != 1 || string(all[0].Progress) != `{"n":2}` {
		t.Fatalf("Progress = %+v, %v; want only the newer count", all, err)
	}

	o80 := remoteObs(other, "192.0.2.1", now)
	o80.Port = 80
	o80.Signature = other.Sign(sig.ObservationMessage(o80.IP, o80.Port, o80.Name, o80.Protocol, o80.Status, o80.SeenAt, o80.Data))
	_, err = st.AddRemoteObservations(ctx, []client.Observation{remoteObs(other, "192.0.2.1", now), remoteObs(other, "192.0.2.1", now.Add(time.Second)), o80, remoteObs(other, "198.51.100.7", now)})
	if err != nil {
		t.Fatal(err)
	}
	counts, err := st.HostCounts(ctx, 24)
	if err != nil {
		t.Fatal(err)
	}
	if c := counts[netip.MustParsePrefix("192.0.2.0/24")]; c.Hosts != 1 || c.OpenPorts != 2 {
		t.Fatalf("192.0.2.0/24: %+v, want 1 host with 2 open ports", c)
	}
	if c := counts[netip.MustParsePrefix("198.51.100.0/24")]; c.Hosts != 1 || c.OpenPorts != 1 || len(counts) != 2 {
		t.Fatalf("HostCounts = %+v", counts)
	}
}
