package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/boidscan/boidscan/internal/fed"
)

func (s *Store) HostCounts(ctx context.Context, blocks []netip.Prefix) (map[netip.Prefix]fed.HostCount, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT b, count(DISTINCT ip), count(*)
		 FROM (SELECT DISTINCT b, o.ip, o.port FROM unnest($1::cidr[]) b JOIN observations o ON o.ip <<= b) x GROUP BY b`, blocks)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[netip.Prefix]fed.HostCount{}
	for rows.Next() {
		var b netip.Prefix
		var c fed.HostCount
		if err := rows.Scan(&b, &c.Hosts, &c.OpenPorts); err != nil {
			return nil, err
		}
		out[b] = c
	}
	return out, rows.Err()
}

func (s *Store) SaveProgress(ctx context.Context, nodeID string, at time.Time, p fed.SignedProgress) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO peer_progress (node_id, counted_at, progress, signature) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (node_id) DO UPDATE SET counted_at = EXCLUDED.counted_at, progress = EXCLUDED.progress, signature = EXCLUDED.signature
		 WHERE EXCLUDED.counted_at > peer_progress.counted_at`,
		nodeID, at, []byte(p.Progress), p.Signature)
	return err
}

func (s *Store) Progress(ctx context.Context) ([]fed.SignedProgress, error) {
	rows, err := s.pool.Query(ctx, `SELECT progress, signature FROM peer_progress ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fed.SignedProgress
	for rows.Next() {
		var p fed.SignedProgress
		var raw []byte
		if err := rows.Scan(&raw, &p.Signature); err != nil {
			return nil, err
		}
		p.Progress = raw
		out = append(out, p)
	}
	return out, rows.Err()
}
