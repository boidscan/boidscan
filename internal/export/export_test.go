package export

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/boidscan/boidscan/pkg/client"
)

type fakeSource []client.Observation

func (f fakeSource) Each(_ context.Context, protocol string, fn func(client.Observation) error) error {
	for _, o := range f {
		if o.Protocol == protocol {
			if err := fn(o); err != nil {
				return err
			}
		}
	}
	return nil
}

func TestIVRE(t *testing.T) {
	seen := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	src := fakeSource{
		{IP: "192.0.2.1", Protocol: "http", Name: "https443", SeenAt: seen, Data: json.RawMessage(`{"status":"success","result":{"response":{}}}`)},
		{IP: "192.0.2.1", Protocol: "ssh", Name: "ssh22", SeenAt: seen, Data: json.RawMessage(`{}`)},
	}
	var buf bytes.Buffer
	n, err := IVRE(context.Background(), src, &buf)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	data := got["data"].(map[string]any)
	if got["ip"] != "192.0.2.1" || got["timestamp"] != "2026-10-10T12:00:00Z" || data["http"] == nil {
		t.Fatalf("unexpected line %s", buf.String())
	}
}
