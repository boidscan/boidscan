package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/boidscan/boidscan/internal/fed"
)

// excluded is an SQL condition: the inet in arg is in an operator exclusion or opted out.
func excluded(arg string) string {
	return `(EXISTS (SELECT 1 FROM exclusions WHERE ` + arg + ` <<= cidr) OR ` + optedOut(arg) + `)`
}

// optedOut is an SQL condition: the newest attestation for the inet in arg is an unexpired add.
func optedOut(arg string) string {
	return `EXISTS (SELECT 1 FROM (SELECT action, expires_at FROM optouts WHERE ip = ` + arg + `
	                ORDER BY signed_at DESC, signature DESC LIMIT 1) latest
	        WHERE latest.action = 'add' AND latest.expires_at > now())`
}

const optOutColumns = `id, host(ip), action, expires_at, signer, signed_at, signature`

func scanOptOut(row pgx.Row) (fed.OptOut, error) {
	var o fed.OptOut
	var ip string
	if err := row.Scan(&o.ID, &ip, &o.Action, &o.Expires, &o.Signer, &o.Time, &o.Signature); err != nil {
		return o, err
	}
	var err error
	o.IP, err = netip.ParseAddr(ip)
	return o, err
}

func collectOptOuts(rows pgx.Rows) ([]fed.OptOut, error) {
	defer rows.Close()
	var out []fed.OptOut
	for rows.Next() {
		o, err := scanOptOut(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) AddOptOuts(ctx context.Context, list []fed.OptOut) (stored, capped int, err error) {
	if len(list) == 0 {
		return 0, 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	// Serialises writers so the daily cap holds; the key is arbitrary.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7262747)`); err != nil {
		return 0, 0, err
	}
	// Older attestations no longer matter: any add they could override has expired.
	if _, err := tx.Exec(ctx, `DELETE FROM optouts WHERE signed_at < now() - $1::float8 * interval '1 second'`, (fed.MaxOptOutAge + 24*time.Hour).Seconds()); err != nil {
		return 0, 0, err
	}
	for _, o := range list {
		var dup bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM optouts WHERE signature = $1)`, o.Signature).Scan(&dup); err != nil {
			return 0, 0, err
		}
		if dup {
			continue
		}
		day := o.Time.UTC().Truncate(24 * time.Hour)
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM optouts WHERE signer = $1 AND signed_at >= $2 AND signed_at < $3`,
			o.Signer, day, day.Add(24*time.Hour)).Scan(&n); err != nil {
			return 0, 0, err
		}
		if n >= fed.MaxOptOutsPerDay {
			capped++
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO optouts (ip, action, expires_at, signer, signed_at, signature) VALUES ($1, $2, $3, $4, $5, $6)`,
			o.IP, o.Action, o.Expires, o.Signer, o.Time, o.Signature); err != nil {
			return 0, 0, err
		}
		stored++
		if _, err := tx.Exec(ctx, `DELETE FROM observations WHERE ip = $1::inet AND `+optedOut("$1::inet"), o.IP); err != nil {
			return 0, 0, err
		}
	}
	return stored, capped, tx.Commit(ctx)
}

func (s *Store) OptOutsAfter(ctx context.Context, after int64, limit int) ([]fed.OptOut, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+optOutColumns+` FROM optouts WHERE id > $1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	return collectOptOuts(rows)
}

func (s *Store) ActiveOptOuts(ctx context.Context) ([]fed.OptOut, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+optOutColumns+` FROM (SELECT DISTINCT ON (ip) * FROM optouts ORDER BY ip, signed_at DESC, signature DESC) latest
		 WHERE action = 'add' AND expires_at > now() ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	return collectOptOuts(rows)
}

func (s *Store) LatestOptOut(ctx context.Context, ip netip.Addr) (fed.OptOut, bool, error) {
	o, err := scanOptOut(s.pool.QueryRow(ctx,
		`SELECT `+optOutColumns+` FROM optouts WHERE ip = $1 ORDER BY signed_at DESC, signature DESC LIMIT 1`, ip))
	if errors.Is(err, pgx.ErrNoRows) {
		return o, false, nil
	}
	return o, err == nil, err
}

func (s *Store) OptOutRequests(ctx context.Context, signer string, ip netip.Addr, since time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM optouts WHERE signer = $1 AND ip = $2 AND signed_at > $3`, signer, ip, since).Scan(&n)
	return n, err
}

func (s *Store) OptOutCursor(ctx context.Context, peer string) (int64, error) {
	var after int64
	err := s.pool.QueryRow(ctx, `SELECT after FROM optout_cursors WHERE peer_id = $1`, peer).Scan(&after)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return after, err
}

func (s *Store) SaveOptOutCursor(ctx context.Context, peer string, after int64) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO optout_cursors (peer_id, after) VALUES ($1, $2) ON CONFLICT (peer_id) DO UPDATE SET after = EXCLUDED.after`, peer, after)
	return err
}
