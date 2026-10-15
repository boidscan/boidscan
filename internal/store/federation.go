package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/pkg/client"
)

func (s *Store) Excluded(ctx context.Context, ip netip.Addr) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT `+excluded("$1::inet"), ip).Scan(&ok)
	return ok, err
}

func (s *Store) ObservationsAfter(ctx context.Context, after int64, limit int) ([]client.Observation, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+obsColumns+` FROM observations WHERE id > $1 AND signature IS NOT NULL ORDER BY id LIMIT $2`, after, limit)
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

func (s *Store) AddRemoteObservations(ctx context.Context, obs []client.Observation) (int, error) {
	if len(obs) == 0 {
		return 0, nil
	}
	b := &pgx.Batch{}
	for _, o := range obs {
		var shaArg *string
		sha, names := CertInfo(o.Data)
		if sha != "" {
			shaArg = &sha
		}
		b.Queue(
			`INSERT INTO observations (node_id, ip, port, name, protocol, status, seen_at, cert_sha256, cert_names, raw, signature, search_text)
			 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
			 WHERE NOT `+excluded("$2::inet")+`
			 ON CONFLICT (signature) DO NOTHING`,
			o.NodeID, o.IP, o.Port, o.Name, o.Protocol, o.Status, o.SeenAt, shaArg, names, []byte(o.Data), o.Signature, SearchText(o.Data, names))
	}
	return execBatch(ctx, s, b)
}

func execBatch(ctx context.Context, s *Store, b *pgx.Batch) (int, error) {
	br := s.pool.SendBatch(ctx, b)
	defer br.Close()
	n := 0
	for range b.Len() {
		tag, err := br.Exec()
		if err != nil {
			return n, err
		}
		n += int(tag.RowsAffected())
	}
	return n, br.Close()
}

const covColumns = `id, block, port_group, catalog, node_id, scanned_at, signature`

func (s *Store) CoverageAfter(ctx context.Context, after int64, limit int) ([]fed.Coverage, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+covColumns+` FROM coverage WHERE id > $1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fed.Coverage
	for rows.Next() {
		var c fed.Coverage
		if err := rows.Scan(&c.ID, &c.Block, &c.Group, &c.Catalog, &c.NodeID, &c.ScannedAt, &c.Signature); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) AddCoverage(ctx context.Context, cov []fed.Coverage) (int, error) {
	if len(cov) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	n := 0
	for _, c := range cov {
		tag, err := tx.Exec(ctx,
			`INSERT INTO coverage (block, port_group, catalog, node_id, scanned_at, signature)
			 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (signature) DO NOTHING`,
			c.Block, c.Group, c.Catalog, c.NodeID, c.ScannedAt, c.Signature)
		if err != nil {
			return 0, err
		}
		n += int(tag.RowsAffected())
		if _, err := tx.Exec(ctx,
			`INSERT INTO unit_latest (block, port_group, scanned_at, node_id) VALUES ($1, $2, $3, $4)
			 ON CONFLICT (block, port_group) DO UPDATE SET scanned_at = EXCLUDED.scanned_at, node_id = EXCLUDED.node_id
			 WHERE EXCLUDED.scanned_at > unit_latest.scanned_at`,
			c.Block, c.Group, c.ScannedAt, c.NodeID); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM leases WHERE block = $1 AND port_group = $2 AND holder = $3`, c.Block, c.Group, c.NodeID); err != nil {
			return 0, err
		}
	}
	return n, tx.Commit(ctx)
}

func (s *Store) ReplicaState(ctx context.Context, home string) (fed.ReplicaState, error) {
	var r fed.ReplicaState
	err := s.pool.QueryRow(ctx,
		`SELECT view, obs_id, cov_id, catch_up, old_view, old_obs_id, old_cov_id FROM replicas WHERE home_id = $1`, home).
		Scan(&r.View, &r.Obs, &r.Cov, &r.CatchUp, &r.Old, &r.OldObs, &r.OldCov)
	if errors.Is(err, pgx.ErrNoRows) {
		return fed.ReplicaState{}, nil
	}
	return r, err
}

func (s *Store) SaveReplicaState(ctx context.Context, home string, r fed.ReplicaState) error {
	view, old := r.View, r.Old
	if view == nil {
		view = []string{}
	}
	if old == nil {
		old = []string{}
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO replicas (home_id, view, obs_id, cov_id, catch_up, old_view, old_obs_id, old_cov_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (home_id) DO UPDATE SET view = EXCLUDED.view, obs_id = EXCLUDED.obs_id, cov_id = EXCLUDED.cov_id,
		     catch_up = EXCLUDED.catch_up, old_view = EXCLUDED.old_view, old_obs_id = EXCLUDED.old_obs_id, old_cov_id = EXCLUDED.old_cov_id`,
		home, view, r.Obs, r.Cov, r.CatchUp, old, r.OldObs, r.OldCov)
	return err
}

func (s *Store) AcquireLease(ctx context.Context, u catalog.Unit, holder string, ttl, minRescan time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO leases (block, port_group, holder, expires_at)
		 SELECT $1::cidr, $2::integer, $3::text, now() + $4::float8 * interval '1 second'
		 WHERE NOT EXISTS (SELECT 1 FROM coverage WHERE block = $1 AND port_group = $2
		                   AND scanned_at > now() - $5::float8 * interval '1 second')
		 ON CONFLICT (block, port_group) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at
		 WHERE leases.holder = EXCLUDED.holder OR leases.expires_at < now()`,
		u.Block, u.Group, holder, ttl.Seconds(), minRescan.Seconds())
	return tag.RowsAffected() == 1, err
}

func (s *Store) ReleaseLease(ctx context.Context, u catalog.Unit, holder string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM leases WHERE block = $1 AND port_group = $2 AND holder = $3`, u.Block, u.Group, holder)
	return err
}

// refillUnitLatest restores the newest remaining coverage of units whose
// unit_latest row was just deleted with the coverage behind it.
const refillUnitLatest = `INSERT INTO unit_latest
	SELECT DISTINCT ON (block, port_group) block, port_group, scanned_at, node_id FROM coverage c
	WHERE NOT EXISTS (SELECT 1 FROM unit_latest u WHERE u.block = c.block AND u.port_group = c.port_group)
	ORDER BY block, port_group, scanned_at DESC`

func (s *Store) UnitStatus(ctx context.Context, blocks []netip.Prefix) ([]fed.UnitStatus, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT coalesce(c.block, l.block), coalesce(c.port_group, l.port_group), c.scanned_at, coalesce(c.node_id, ''), coalesce(l.holder, '')
		 FROM (SELECT * FROM unit_latest WHERE block = ANY($1)) c
		 FULL JOIN (SELECT * FROM leases WHERE expires_at > now() AND block = ANY($1)) l ON c.block = l.block AND c.port_group = l.port_group
		 ORDER BY 1, 2`, blocks)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fed.UnitStatus
	for rows.Next() {
		var u fed.UnitStatus
		var at *time.Time
		if err := rows.Scan(&u.Block, &u.Group, &at, &u.ScannedBy, &u.LeasedBy); err != nil {
			return nil, err
		}
		if at != nil {
			u.ScannedAt = *at
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) RecentRun(ctx context.Context, u catalog.Unit, d time.Duration) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM scan_runs WHERE block = $1 AND port_group = $2 AND finished_at IS NOT NULL
		                AND error IS NULL AND started_at > now() - $3::float8 * interval '1 second')`,
		u.Block, u.Group, d.Seconds()).Scan(&ok)
	return ok, err
}

func (s *Store) SweepRuns(ctx context.Context, limit int) ([]fed.Run, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, block, port_group, started_at, finished_at, coalesce(error, '')
		 FROM scan_runs WHERE block IS NOT NULL ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fed.Run
	for rows.Next() {
		var r fed.Run
		var finished *time.Time
		if err := rows.Scan(&r.ID, &r.Block, &r.Group, &r.StartedAt, &finished, &r.Error); err != nil {
			return nil, err
		}
		if finished != nil {
			r.FinishedAt = *finished
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
