package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/boidscan/boidscan/internal/fed"
)

func (s *Store) SavePeer(ctx context.Context, r fed.Record) (saved, isNew bool, err error) {
	err = s.pool.QueryRow(ctx,
		`INSERT INTO peers (id, name, endpoint, contact, project_url, version, catalog, root, policy_serial, emergency_pause, record_time, signature)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (id) DO UPDATE SET
		     name = EXCLUDED.name, endpoint = EXCLUDED.endpoint, contact = EXCLUDED.contact,
		     project_url = EXCLUDED.project_url, version = EXCLUDED.version, catalog = EXCLUDED.catalog,
		     root = EXCLUDED.root, policy_serial = EXCLUDED.policy_serial, emergency_pause = EXCLUDED.emergency_pause,
		     record_time = EXCLUDED.record_time, signature = EXCLUDED.signature,
		     verified_at = CASE WHEN peers.endpoint = EXCLUDED.endpoint THEN peers.verified_at END,
		     state = CASE WHEN peers.endpoint = EXCLUDED.endpoint THEN peers.state ELSE 'new' END
		 WHERE EXCLUDED.record_time > peers.record_time
		 RETURNING xmax = 0`,
		r.ID, r.Name, r.Endpoint, r.Contact, r.ProjectURL, r.Version, r.Catalog, r.Root, int64(r.PolicySerial), r.EmergencyPause, r.Time, r.Signature).Scan(&isNew)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	return err == nil, isNew, err
}

func (s *Store) Peers(ctx context.Context) ([]fed.Peer, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, endpoint, contact, project_url, version, catalog, root, policy_serial, emergency_pause, record_time, signature, first_seen, verified_at IS NOT NULL, state
		 FROM peers ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fed.Peer
	for rows.Next() {
		var p fed.Peer
		var serial int64
		if err := rows.Scan(&p.ID, &p.Name, &p.Endpoint, &p.Contact, &p.ProjectURL, &p.Version, &p.Catalog, &p.Root, &serial, &p.EmergencyPause, &p.Time, &p.Signature, &p.FirstSeen, &p.Verified, &p.State); err != nil {
			return nil, err
		}
		p.PolicySerial = uint64(serial)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) MarkVerified(ctx context.Context, id, endpoint string) error {
	_, err := s.pool.Exec(ctx, `UPDATE peers SET verified_at = now() WHERE id = $1 AND endpoint = $2`, id, endpoint)
	return err
}

func (s *Store) SetPeerState(ctx context.Context, id, state string) error {
	_, err := s.pool.Exec(ctx, `UPDATE peers SET state = $2 WHERE id = $1`, id, state)
	return err
}

func (s *Store) DeletePeer(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM peers WHERE id = $1`, id)
	return err
}
