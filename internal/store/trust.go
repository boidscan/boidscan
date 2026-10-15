package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/pkg/client"
)

func (s *Store) AddSample(ctx context.Context, sm fed.Sample) error {
	evidence, err := json.Marshal(sm.Evidence)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO samples (key, subject, kind, scanner, ip, port, name, reported_open, reported_fp, scanned_at, evidence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (subject) DO NOTHING`,
		sm.Key, sm.Subject, sm.Kind, sm.Scanner, sm.Target.IP, int32(sm.Target.Port), sm.Target.Name,
		sm.ReportedOpen, sm.ReportedFP, sm.ScannedAt, evidence)
	return err
}

func (s *Store) OpenSamples(ctx context.Context, limit int) ([]fed.Sample, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, key, subject, kind, scanner, host(ip), port, name, reported_open, reported_fp, scanned_at, evidence, checkers, created_at
		 FROM samples WHERE decided_at IS NULL ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fed.Sample
	for rows.Next() {
		var sm fed.Sample
		var ip string
		var port int32
		var evidence []byte
		if err := rows.Scan(&sm.ID, &sm.Key, &sm.Subject, &sm.Kind, &sm.Scanner, &ip, &port, &sm.Target.Name,
			&sm.ReportedOpen, &sm.ReportedFP, &sm.ScannedAt, &evidence, &sm.Checkers, &sm.CreatedAt); err != nil {
			return nil, err
		}
		sm.Target.IP, sm.Target.Port = netip.MustParseAddr(ip), uint16(port)
		if err := json.Unmarshal(evidence, &sm.Evidence); err != nil {
			return nil, err
		}
		out = append(out, sm)
	}
	return out, rows.Err()
}

func (s *Store) SetCheckers(ctx context.Context, id int64, checkers []string) error {
	_, err := s.pool.Exec(ctx, `UPDATE samples SET checkers = $2 WHERE id = $1`, id, checkers)
	return err
}

func (s *Store) SaveVote(ctx context.Context, id int64, v fed.Vote) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sample_votes (sample_id, checker, open, fingerprint, unavailable) VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (sample_id, checker) DO NOTHING`,
		id, v.Checker, v.Open, v.Fingerprint, v.Unavailable)
	return err
}

func (s *Store) Votes(ctx context.Context, id int64) ([]fed.Vote, error) {
	rows, err := s.pool.Query(ctx, `SELECT checker, open, fingerprint, unavailable FROM sample_votes WHERE sample_id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fed.Vote
	for rows.Next() {
		var v fed.Vote
		if err := rows.Scan(&v.Checker, &v.Open, &v.Fingerprint, &v.Unavailable); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) Decide(ctx context.Context, id int64, verdict string) error {
	_, err := s.pool.Exec(ctx, `UPDATE samples SET verdict = $2, decided_at = now() WHERE id = $1`, id, verdict)
	return err
}

func (s *Store) Score(ctx context.Context, scanner string, window int) (fed.Score, error) {
	var sc fed.Score
	rows, err := s.pool.Query(ctx,
		`SELECT kind, verdict FROM samples WHERE scanner = $1 AND decided_at IS NOT NULL ORDER BY decided_at DESC LIMIT $2`,
		scanner, window)
	if err != nil {
		return sc, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, verdict string
		if err := rows.Scan(&kind, &verdict); err != nil {
			return sc, err
		}
		sc.Add(kind, verdict)
	}
	return sc, rows.Err()
}

func (s *Store) CoverageEvidence(ctx context.Context, u catalog.Unit, ports []uint16, scanner string, since, before time.Time, limit int) ([]client.Observation, error) {
	ps := make([]int32, len(ports))
	for i, p := range ports {
		ps[i] = int32(p)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+obsColumns+` FROM observations
		 WHERE ip <<= $1 AND port = ANY($2) AND status = 'success' AND node_id <> $3 AND signature IS NOT NULL
		   AND seen_at >= $4 AND seen_at < $5
		 ORDER BY seen_at DESC LIMIT $6`,
		u.Block, ps, scanner, since, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []client.Observation
	for rows.Next() {
		o, err := scanObservation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) Reported(ctx context.Context, scanner string, t fed.CheckTarget, since time.Time) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM observations WHERE node_id = $1 AND ip = $2 AND port = $3 AND name = $4 AND seen_at >= $5)`,
		scanner, t.IP, int32(t.Port), t.Name, since).Scan(&ok)
	return ok, err
}

func (s *Store) SetTrust(ctx context.Context, id, trust string, lowReach bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE peers SET trust = $2, low_reach = $3 WHERE id = $1`, id, trust, lowReach)
	return err
}

func (s *Store) DropShunned(ctx context.Context, id string) error {
	return s.execTx(ctx, []any{id},
		`DELETE FROM observations o WHERE node_id = $1 AND NOT EXISTS
		     (SELECT 1 FROM samples s WHERE s.subject = o.signature AND s.verdict IN ('pass', 'change'))`,
		`DELETE FROM coverage WHERE node_id = $1`,
		`DELETE FROM leases WHERE holder = $1`,
		`DELETE FROM optouts WHERE signer = $1`,
		`DELETE FROM optout_cursors WHERE signer = $1`)
}

func (s *Store) DropCoverage(ctx context.Context, id string) error {
	return s.execTx(ctx, []any{id}, `DELETE FROM coverage WHERE node_id = $1`, `DELETE FROM leases WHERE holder = $1`)
}

// execTx runs statements that take the same arguments in one transaction.
func (s *Store) execTx(ctx context.Context, args []any, queries ...string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, q := range queries {
		if _, err := tx.Exec(ctx, q, args...); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) AddCheck(ctx context.Context, c fed.Check) error {
	evidence, err := json.Marshal(c.Evidence)
	if err != nil {
		return err
	}
	var open, unavailable *bool
	var fp *string
	if c.Done {
		open, fp, unavailable = &c.Result.Open, &c.Result.Fingerprint, &c.Result.Unavailable
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO checks (requester, key, kind, scanner, ip, port, name, evidence, done_at, open, fingerprint, unavailable)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CASE WHEN $9 THEN now() END, $10, $11, $12)
		 ON CONFLICT (requester, key) DO NOTHING`,
		c.Requester, c.Key, c.Kind, c.Scanner, c.Target.IP, int32(c.Target.Port), c.Target.Name, evidence, c.Done, open, fp, unavailable)
	return err
}

const checkColumns = `id, requester, key, kind, scanner, host(ip), port, name, evidence, done_at IS NOT NULL,
	coalesce(open, false), coalesce(fingerprint, ''), coalesce(unavailable, false)`

func scanCheck(row pgx.Row) (fed.Check, error) {
	var c fed.Check
	var ip string
	var port int32
	var evidence []byte
	err := row.Scan(&c.ID, &c.Requester, &c.Key, &c.Kind, &c.Scanner, &ip, &port, &c.Target.Name, &evidence, &c.Done,
		&c.Result.Open, &c.Result.Fingerprint, &c.Result.Unavailable)
	if err != nil {
		return c, err
	}
	c.Target.IP, c.Target.Port = netip.MustParseAddr(ip), uint16(port)
	return c, json.Unmarshal(evidence, &c.Evidence)
}

func (s *Store) PendingChecks(ctx context.Context, limit int) ([]fed.Check, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+checkColumns+` FROM checks WHERE done_at IS NULL ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fed.Check
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) FinishCheck(ctx context.Context, id int64, r fed.CheckResult) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE checks SET done_at = now(), open = $2, fingerprint = $3, unavailable = $4 WHERE id = $1`,
		id, r.Open, r.Fingerprint, r.Unavailable)
	return err
}

func (s *Store) CheckByKey(ctx context.Context, requester, key string) (fed.Check, bool, error) {
	c, err := scanCheck(s.pool.QueryRow(ctx, `SELECT `+checkColumns+` FROM checks WHERE requester = $1 AND key = $2`, requester, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, false, nil
	}
	return c, err == nil, err
}

func (s *Store) RecentCheck(ctx context.Context, t fed.CheckTarget, since time.Time) (fed.CheckResult, bool, error) {
	var r fed.CheckResult
	err := s.pool.QueryRow(ctx,
		`SELECT open, fingerprint, unavailable FROM checks
		 WHERE ip = $1 AND port = $2 AND name = $3 AND done_at >= $4 ORDER BY done_at DESC LIMIT 1`,
		t.IP, int32(t.Port), t.Name, since).Scan(&r.Open, &r.Fingerprint, &r.Unavailable)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}
