// Package store persists scan runs, observations, exclusions and peers in PostgreSQL.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/grab"
	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/pkg/client"
	"github.com/boidscan/boidscan/pkg/sig"
)

//go:embed migrations/*.sql
var migrations embed.FS

const maxLimit = 1000

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialises concurrent migrators; the key is arbitrary.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7262746)`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY)`); err != nil {
		return err
	}
	var current int
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		base := strings.TrimPrefix(name, "migrations/")
		v, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: bad version prefix", base)
		}
		if v <= current {
			continue
		}
		sql, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("migration %s: %w", base, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, v); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) StartRun(ctx context.Context, nodeID string, targets []netip.Prefix, ports []uint16) (int64, error) {
	ts := make([]string, len(targets))
	for i, t := range targets {
		ts[i] = t.String()
	}
	ps := make([]int32, len(ports))
	for i, p := range ports {
		ps[i] = int32(p)
	}
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO scan_runs (node_id, targets, ports) VALUES ($1, $2, $3) RETURNING id`,
		nodeID, ts, ps).Scan(&id)
	return id, err
}

func (s *Store) FinishRun(ctx context.Context, id int64, runErr error) error {
	var msg *string
	if runErr != nil {
		m := runErr.Error()
		msg = &m
	}
	_, err := s.pool.Exec(ctx, `UPDATE scan_runs SET finished_at = now(), error = $2 WHERE id = $1`, id, msg)
	return err
}

// AddObservation stores o signed by k, the node that scanned it.
func (s *Store) AddObservation(ctx context.Context, runID int64, k fed.Signer, o grab.Observation) error {
	sha, names := CertInfo(o.Raw)
	var shaArg *string
	if sha != "" {
		shaArg = &sha
	}
	ip := o.IP.Unmap().String()
	seen := time.Now().UTC().Truncate(time.Microsecond)
	signature := k.Sign(sig.ObservationMessage(ip, int(o.Port), o.Name, o.Protocol, o.Status, seen, o.Raw))
	// The guard catches exclusions added while a scan is already running.
	_, err := s.pool.Exec(ctx,
		`INSERT INTO observations (run_id, node_id, ip, port, name, protocol, status, seen_at, cert_sha256, cert_names, raw, signature)
		 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		 WHERE NOT EXISTS (SELECT 1 FROM exclusions WHERE $3::inet <<= cidr)`,
		runID, k.ID(), ip, int32(o.Port), o.Name, o.Protocol, o.Status, seen, shaArg, names, []byte(o.Raw), signature)
	return err
}

const obsColumns = `id, run_id, node_id, host(ip), port, name, protocol, status, seen_at, coalesce(cert_sha256, ''), coalesce(cert_names, '{}'), raw, signature`

func scanObservation(row pgx.Row) (client.Observation, error) {
	var o client.Observation
	var raw []byte
	err := row.Scan(&o.ID, &o.RunID, &o.NodeID, &o.IP, &o.Port, &o.Name, &o.Protocol, &o.Status, &o.SeenAt, &o.CertSHA256, &o.CertNames, &raw, &o.Signature)
	o.Data = raw
	return o, err
}

// Host returns the latest observation for every port and module seen on ip.
func (s *Store) Host(ctx context.Context, ip netip.Addr) (client.Host, error) {
	h := client.Host{IP: ip.String(), Services: []client.Observation{}}
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT ON (port, name) `+obsColumns+`
		 FROM observations WHERE ip = $1 ORDER BY port, name, seen_at DESC`, ip)
	if err != nil {
		return h, err
	}
	defer rows.Close()
	for rows.Next() {
		o, err := scanObservation(rows)
		if err != nil {
			return h, err
		}
		h.Services = append(h.Services, o)
	}
	return h, rows.Err()
}

func buildSearch(q client.Query) (string, []any, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if q.CIDR != "" {
		p, err := netset.ParsePrefix(q.CIDR)
		if err != nil {
			return "", nil, fmt.Errorf("cidr: %w", err)
		}
		add("ip <<= ?", p)
	}
	if q.Port != 0 {
		if q.Port < 1 || q.Port > 65535 {
			return "", nil, errors.New("port out of range")
		}
		add("port = ?", q.Port)
	}
	if q.Text != "" {
		add("raw::text ILIKE ?", "%"+escapeLike(q.Text)+"%")
	}
	if q.Cert != "" {
		args = append(args, strings.ToLower(q.Cert))
		n := "$" + strconv.Itoa(len(args))
		where = append(where, "(cert_sha256 = "+n+" OR cert_names @> ARRAY["+n+"])")
	}
	if q.Before > 0 {
		add("id < ?", q.Before)
	}
	sql := `SELECT ` + obsColumns + ` FROM observations`
	if len(where) > 0 {
		sql += ` WHERE ` + strings.Join(where, " AND ")
	}
	args = append(args, clampLimit(q.Limit)+1)
	sql += ` ORDER BY id DESC LIMIT $` + strconv.Itoa(len(args))
	return sql, args, nil
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func clampLimit(n int) int {
	if n <= 0 {
		return 100
	}
	return min(n, maxLimit)
}

// ErrBadQuery wraps query validation errors so callers can map them to 400.
var ErrBadQuery = errors.New("bad query")

func (s *Store) Search(ctx context.Context, q client.Query) (client.Page, error) {
	page := client.Page{Results: []client.Observation{}}
	sql, args, err := buildSearch(q)
	if err != nil {
		return page, fmt.Errorf("%w: %v", ErrBadQuery, err)
	}
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	limit := clampLimit(q.Limit)
	for rows.Next() {
		o, err := scanObservation(rows)
		if err != nil {
			return page, err
		}
		if len(page.Results) == limit {
			page.Next = page.Results[limit-1].ID
			break
		}
		page.Results = append(page.Results, o)
	}
	return page, rows.Err()
}

// Each streams observations in id order, for export.
func (s *Store) Each(ctx context.Context, protocol string, fn func(client.Observation) error) error {
	rows, err := s.pool.Query(ctx, `SELECT `+obsColumns+` FROM observations WHERE ($1 = '' OR protocol = $1) ORDER BY id`, protocol)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		o, err := scanObservation(rows)
		if err != nil {
			return err
		}
		if err := fn(o); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Exclusion is a range this node's operator chose not to scan.
type Exclusion struct {
	Prefix  netip.Prefix
	Note    string
	AddedAt time.Time
}

func (s *Store) AddExclusion(ctx context.Context, p netip.Prefix, note string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO exclusions (cidr, note) VALUES ($1, $2) ON CONFLICT (cidr) DO NOTHING`, p, note)
	return err
}

func (s *Store) RemoveExclusion(ctx context.Context, p netip.Prefix) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM exclusions WHERE cidr = $1`, p)
	return tag.RowsAffected() > 0, err
}

func (s *Store) Exclusions(ctx context.Context) ([]Exclusion, error) {
	rows, err := s.pool.Query(ctx, `SELECT cidr, note, added_at FROM exclusions ORDER BY cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Exclusion
	for rows.Next() {
		var e Exclusion
		if err := rows.Scan(&e.Prefix, &e.Note, &e.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ExclusionSet(ctx context.Context) (*netset.Set, error) {
	list, err := s.Exclusions(ctx)
	if err != nil {
		return nil, err
	}
	set := &netset.Set{}
	for _, e := range list {
		set.Add(e.Prefix)
	}
	return set, nil
}

// PurgeRange deletes stored observations inside p.
func (s *Store) PurgeRange(ctx context.Context, p netip.Prefix) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM observations WHERE ip <<= $1`, p)
	return tag.RowsAffected(), err
}
