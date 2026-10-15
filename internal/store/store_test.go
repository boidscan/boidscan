package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"github.com/boidscan/boidscan/internal/grab"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/pkg/client"
)

// openTestStore needs a disposable database in BOIDSCAN_TEST_DB; build.sh and CI provide one.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("BOIDSCAN_TEST_DB")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("BOIDSCAN_TEST_DB must be set in CI")
		}
		t.Skip("BOIDSCAN_TEST_DB not set")
	}
	ctx := context.Background()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	_, err = st.pool.Exec(ctx, `DROP TABLE IF EXISTS observations, scan_runs, optouts, exclusions, peers, coverage, leases, replicas, policies, policy_pauses, samples, sample_votes, checks, optout_cursors, schema_migrations CASCADE`)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return st
}

var testKey, _ = identity.Generate()

func obs(ip string, port uint16, name, protocol, raw string) grab.Observation {
	return grab.Observation{IP: netip.MustParseAddr(ip), Port: port, Name: name, Protocol: protocol, Status: "success", Raw: json.RawMessage(raw)}
}

const tlsRaw = `{"status":"success","protocol":"http","result":{"response":{"request":{"tls_log":{"handshake_log":{"server_certificates":{"certificate":{"parsed":{"fingerprint_sha256":"aa11","extensions":{"subject_alt_name":{"dns_names":["shop.example.org"]}}}}}}}}}}}`

func TestMigrateIdempotent(t *testing.T) {
	st := openTestStore(t)
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestObservationsRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	run, err := st.StartRun(ctx, testKey.ID(), []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, []uint16{22, 443}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []grab.Observation{
		obs("192.0.2.1", 22, "ssh22", "ssh", `{"status":"success","result":{"server_id":{"raw":"SSH-2.0-OpenSSH_9.6"}}}`),
		obs("192.0.2.1", 22, "ssh22", "ssh", `{"status":"success","result":{"server_id":{"raw":"SSH-2.0-OpenSSH_10.0"}}}`),
		obs("192.0.2.1", 443, "https443", "http", tlsRaw),
		// NUL in a banner must be storable; jsonb would reject it.
		obs("192.0.2.2", 23, "telnet23", "telnet", `{"status":"success","result":{"banner":"\u0000ÿLogin:"}}`),
	} {
		if err := st.AddObservation(ctx, run, testKey, o); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.FinishRun(ctx, run, nil); err != nil {
		t.Fatal(err)
	}

	h, err := st.Host(ctx, netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Services) != 2 {
		t.Fatalf("host services = %d, want latest per port (2)", len(h.Services))
	}
	if string(h.Services[0].Data) == "" || !json.Valid(h.Services[0].Data) {
		t.Fatal("raw data not returned")
	}
	for _, o := range h.Services {
		if err := o.Verify(); err != nil || o.NodeID != testKey.ID() {
			t.Errorf("%s:%d: node %s, %v", o.IP, o.Port, o.NodeID, err)
		}
	}
	var ssh struct {
		Result struct {
			ServerID struct{ Raw string } `json:"server_id"`
		}
	}
	json.Unmarshal(h.Services[0].Data, &ssh)
	if ssh.Result.ServerID.Raw != "SSH-2.0-OpenSSH_10.0" {
		t.Errorf("host did not return the latest ssh observation: %q", ssh.Result.ServerID.Raw)
	}

	for name, tc := range map[string]struct {
		q    client.Query
		want int
	}{
		"all":                {client.Query{}, 4},
		"cidr":               {client.Query{CIDR: "192.0.2.2/32"}, 1},
		"port":               {client.Query{Port: 22}, 2},
		"text":               {client.Query{Text: "openssh_10"}, 1},
		"text in nul banner": {client.Query{Text: "LOGIN:"}, 1},
		"cert by san":        {client.Query{Cert: "SHOP.example.org"}, 1},
		"cert by sha":        {client.Query{Cert: "AA11"}, 1},
		"like escape":        {client.Query{Text: "%"}, 0},
	} {
		page, err := st.Search(ctx, tc.q)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(page.Results) != tc.want {
			t.Errorf("%s: got %d results, want %d", name, len(page.Results), tc.want)
		}
	}

	var ids []int64
	q := client.Query{Limit: 3}
	for {
		page, err := st.Search(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range page.Results {
			ids = append(ids, o.ID)
		}
		if page.Next == 0 {
			break
		}
		q.Before = page.Next
	}
	if len(ids) != 4 || ids[0] < ids[3] {
		t.Errorf("paging returned %v, want 4 ids newest first", ids)
	}

	var exported int
	err = st.Each(ctx, "http", func(o client.Observation) error {
		exported++
		if o.CertSHA256 != "aa11" {
			t.Errorf("cert sha not stored: %q", o.CertSHA256)
		}
		return nil
	})
	if err != nil || exported != 1 {
		t.Errorf("Each(http) = %d, %v", exported, err)
	}
}

func TestExclusion(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	run, _ := st.StartRun(ctx, testKey.ID(), []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, []uint16{80}, nil)
	st.AddObservation(ctx, run, testKey, obs("198.51.100.7", 80, "http80", "http", `{}`))
	st.AddObservation(ctx, run, testKey, obs("198.51.100.200", 80, "http80", "http", `{}`))

	p := netip.MustParsePrefix("198.51.100.0/25")
	if err := st.AddExclusion(ctx, p, "hoster forbids it"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddExclusion(ctx, p, "again"); err != nil {
		t.Fatalf("duplicate exclusion must be a no-op: %v", err)
	}
	n, err := st.PurgeRange(ctx, p)
	if err != nil || n != 1 {
		t.Fatalf("purged %d, %v; want 1", n, err)
	}

	// An exclusion added mid-scan must also block late inserts.
	if err := st.AddObservation(ctx, run, testKey, obs("198.51.100.8", 80, "http80", "http", `{}`)); err != nil {
		t.Fatal(err)
	}
	page, _ := st.Search(ctx, client.Query{CIDR: "198.51.100.0/24"})
	if len(page.Results) != 1 || page.Results[0].IP != "198.51.100.200" {
		t.Fatalf("unexpected results after exclusion: %+v", page.Results)
	}

	set, err := st.ExclusionSet(ctx)
	if err != nil || !set.Contains(netip.MustParseAddr("198.51.100.9")) {
		t.Fatalf("ExclusionSet = %v, %v", set, err)
	}
	list, _ := st.Exclusions(ctx)
	if len(list) != 1 || list[0].Prefix != p || list[0].Note != "hoster forbids it" {
		t.Fatalf("Exclusions = %+v", list)
	}
	ok, err := st.RemoveExclusion(ctx, p)
	if err != nil || !ok {
		t.Fatalf("RemoveExclusion = %v, %v", ok, err)
	}
	if ok, _ := st.RemoveExclusion(ctx, p); ok {
		t.Fatal("second remove must report nothing removed")
	}
}

func TestBackfillSearchText(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	run, _ := st.StartRun(ctx, testKey.ID(), []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, []uint16{21}, nil)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if err := st.AddObservation(ctx, run, testKey, obs(ip, 21, "ftp21", "ftp", `{"status":"success","result":{"banner":"220 ProFTPD Server"}}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.pool.Exec(ctx, `UPDATE observations SET search_text = NULL`); err != nil {
		t.Fatal(err)
	}
	if n, err := st.SearchTextPending(ctx); err != nil || n != 2 {
		t.Fatalf("pending = %d, %v; want 2", n, err)
	}
	if n, err := st.BackfillSearchText(ctx); err != nil || n != 2 {
		t.Fatalf("backfilled %d, %v; want 2", n, err)
	}
	if n, _ := st.SearchTextPending(ctx); n != 0 {
		t.Fatalf("pending after backfill = %d", n)
	}
	page, err := st.Search(ctx, client.Query{Text: "proftpd"})
	if err != nil || len(page.Results) != 2 {
		t.Fatalf("search after backfill = %d results, %v", len(page.Results), err)
	}
}
