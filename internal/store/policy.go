package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/boidscan/boidscan/internal/flockpolicy"
)

// Policies were verified before they were stored, so reading them only parses.
func (s *Store) Policies(ctx context.Context) ([]flockpolicy.Policy, error) {
	rows, err := s.pool.Query(ctx, `SELECT serial, document FROM policies ORDER BY serial`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []flockpolicy.Policy
	for rows.Next() {
		var serial int64
		var raw []byte
		if err := rows.Scan(&serial, &raw); err != nil {
			return nil, err
		}
		var d flockpolicy.Document
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("stored policy %d: %w", serial, err)
		}
		p, err := flockpolicy.Parse(d)
		if err != nil {
			return nil, fmt.Errorf("stored policy %d: %w", serial, err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) PolicyState(ctx context.Context) (flockpolicy.State, error) {
	st := flockpolicy.State{Expires: map[uint64]time.Time{}}
	rows, err := s.pool.Query(ctx, `SELECT serial, expires_at FROM policies`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	var latest int64
	for rows.Next() {
		var serial int64
		var expires time.Time
		if err := rows.Scan(&serial, &expires); err != nil {
			return st, err
		}
		st.Expires[uint64(serial)] = expires
		latest = max(latest, serial)
	}
	if err := rows.Err(); err != nil {
		return st, err
	}
	if latest == 0 {
		return st, nil
	}

	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT document FROM policies WHERE serial = $1`, latest).Scan(&raw); err != nil {
		return st, err
	}
	var d flockpolicy.Document
	if err := json.Unmarshal(raw, &d); err != nil {
		return st, fmt.Errorf("stored policy %d: %w", latest, err)
	}
	p, err := flockpolicy.Parse(d)
	if err != nil {
		return st, fmt.Errorf("stored policy %d: %w", latest, err)
	}
	st.Latest = &p

	err = s.pool.QueryRow(ctx, `SELECT document FROM policy_pauses WHERE serial = $1`, latest).Scan(&raw)
	if err == nil {
		var pd flockpolicy.Document
		if err := json.Unmarshal(raw, &pd); err != nil {
			return st, fmt.Errorf("stored emergency pause %d: %w", latest, err)
		}
		pause, err := flockpolicy.ParsePause(pd)
		if err != nil {
			return st, fmt.Errorf("stored emergency pause %d: %w", latest, err)
		}
		st.Pause = &pause
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return st, err
	}
	return st, nil
}

func (s *Store) AddPolicy(ctx context.Context, p flockpolicy.Policy) (bool, error) {
	raw, err := json.Marshal(p.Doc)
	if err != nil {
		return false, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	// Concurrent adopters of the same policy wait here instead of failing on the key.
	if _, err := tx.Exec(ctx, `LOCK TABLE policies IN EXCLUSIVE MODE`); err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO policies (serial, document, expires_at)
		 SELECT $1, $2, $3 WHERE NOT EXISTS (SELECT 1 FROM policies WHERE serial >= $1)`,
		int64(p.Serial), raw, p.Expires)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, tx.Commit(ctx)
}

func (s *Store) AddPause(ctx context.Context, p flockpolicy.Pause) (bool, error) {
	raw, err := json.Marshal(p.Doc)
	if err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO policy_pauses (serial, document, expires_at) VALUES ($1, $2, $3) ON CONFLICT (serial) DO NOTHING`,
		int64(p.Serial), raw, p.Expires)
	return tag.RowsAffected() == 1, err
}

func (s *Store) SyncRevoked(ctx context.Context, ids []string, self string) error {
	if ids == nil {
		ids = []string{}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, q := range []string{
		`UPDATE peers SET state = 'revoked' WHERE id = ANY($1)`,
		`UPDATE peers SET state = 'new', verified_at = NULL WHERE state = 'revoked' AND NOT id = ANY($1)`,
		`DELETE FROM observations o WHERE node_id = ANY($1) AND node_id <> $2 AND NOT EXISTS
		     (SELECT 1 FROM samples s WHERE s.verdict IN ('pass', 'change') AND s.scanner = o.node_id AND s.ip = o.ip
		     AND s.port = o.port AND s.name = o.name AND s.scanned_at BETWEEN coalesce(o.first_seen_at, o.seen_at) AND o.seen_at)`,
		`DELETE FROM coverage WHERE node_id = ANY($1) AND node_id <> $2`,
		`DELETE FROM unit_latest WHERE node_id = ANY($1) AND node_id <> $2`,
		refillUnitLatest,
		`DELETE FROM leases WHERE holder = ANY($1)`,
		`DELETE FROM optouts WHERE signer = ANY($1) AND signer <> $2`,
		`DELETE FROM optout_cursors WHERE signer = ANY($1) AND signer <> $2`,
	} {
		var args []any
		if strings.Contains(q, "$1") {
			args = append(args, ids)
		}
		if strings.Contains(q, "$2") {
			args = append(args, self)
		}
		if _, err := tx.Exec(ctx, q, args...); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
