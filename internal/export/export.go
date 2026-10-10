// Package export writes stored observations as zgrab2 JSON lines for `ivre scan2db`.
package export

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/boidscan/boidscan/pkg/client"
)

// IVRE only parses the "http" and "jarm" zgrab2 data keys:
// https://github.com/ivre/ivre/blob/master/ivre/zgrabout.py
const ivreProtocol = "http"

type line struct {
	IP        string                     `json:"ip"`
	Timestamp string                     `json:"timestamp"`
	Data      map[string]json.RawMessage `json:"data"`
}

type Source interface {
	Each(ctx context.Context, protocol string, fn func(client.Observation) error) error
}

// IVRE writes one line per HTTP observation, keyed "http" as IVRE expects.
func IVRE(ctx context.Context, src Source, w io.Writer) (int, error) {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	n := 0
	err := src.Each(ctx, ivreProtocol, func(o client.Observation) error {
		n++
		return enc.Encode(line{
			IP:        o.IP,
			Timestamp: o.SeenAt.UTC().Format(time.RFC3339),
			Data:      map[string]json.RawMessage{ivreProtocol: o.Data},
		})
	})
	if err != nil {
		return n, err
	}
	return n, bw.Flush()
}
