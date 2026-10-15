// Package store persists scan runs, observations, exclusions, peers, coverage
// and leases in PostgreSQL.
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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/boidscan/boidscan/internal/catalog"
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

// StartRun records a scan. unit is nil for manual scans.
func (s *Store) StartRun(ctx context.Context, nodeID string, targets []netip.Prefix, ports []uint16, unit *catalog.Unit) (int64, error) {
	ts := make([]string, len(targets))
	for i, t := range targets {
		ts[i] = t.String()
	}
	ps := make([]int32, len(ports))
	for i, p := range ports {
		ps[i] = int32(p)
	}
	var block *netip.Prefix
	var group *int
	if unit != nil {
		block, group = &unit.Block, &unit.Group
	}
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO scan_runs (node_id, targets, ports, block, port_group) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		nodeID, ts, ps, block, group).Scan(&id)
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
	ip := o.IP.Unmap().String()
	seen := time.Now().UTC().Truncate(time.Microsecond)
	signature := k.Sign(sig.ObservationMessage(ip, int(o.Port), o.Name, o.Protocol, o.Status, seen, o.Raw))
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := saveObservation(ctx, tx, &runID, client.Observation{NodeID: k.ID(), IP: ip, Port: int(o.Port), Name: o.Name,
			Protocol: o.Protocol, Status: o.Status, SeenAt: seen, Data: o.Raw, Signature: signature})
		return err
	})
}

// saveObservation stores a signed result as the newest version of its service
// when it says something else than the stored newest version, and otherwise
// as that version seen again. A result older than the newest version only
// moves the first sighting of a stored version back, or is kept as an older
// version. It reports whether a row was added or seen again.
func saveObservation(ctx context.Context, tx pgx.Tx, runID *int64, o client.Observation) (bool, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, o.IP+" "+strconv.Itoa(o.Port)+" "+o.Name+" "+o.NodeID); err != nil {
		return false, err
	}
	// The exclusion guard catches exclusions and opt-outs added while a scan is already running.
	var skip bool
	if err := tx.QueryRow(ctx, `SELECT `+excluded("$1::inet")+` OR EXISTS (SELECT 1 FROM observations WHERE signature = $2)`,
		o.IP, o.Signature).Scan(&skip); err != nil || skip {
		return false, err
	}
	sha, names := CertInfo(o.Data)
	var shaArg *string
	if sha != "" {
		shaArg = &sha
	}
	key := ChangeKey(o.Protocol, o.Status, o.Data)
	var curID int64
	var curKey *string
	var curSeen time.Time
	err := tx.QueryRow(ctx, `SELECT id, change_key, seen_at FROM observations WHERE ip = $1 AND port = $2 AND name = $3 AND node_id = $4
		ORDER BY seen_at DESC LIMIT 1`, o.IP, int32(o.Port), o.Name, o.NodeID).Scan(&curID, &curKey, &curSeen)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	switch {
	case found && o.SeenAt.After(curSeen) && curKey != nil && *curKey == key:
		_, err := tx.Exec(ctx,
			`UPDATE observations SET run_id = coalesce($2, run_id), protocol = $3, status = $4, seen_at = $5, cert_sha256 = $6,
			        cert_names = $7, raw = $8, signature = $9, search_text = $10, seq = nextval('observations_seq')
			 WHERE id = $1`,
			curID, runID, o.Protocol, o.Status, o.SeenAt, shaArg, names, []byte(o.Data), o.Signature, SearchText(o.Data, names))
		return err == nil, err
	case found && !o.SeenAt.After(curSeen):
		tag, err := tx.Exec(ctx, `UPDATE observations SET first_seen_at = least(coalesce(first_seen_at, seen_at), $5)
			WHERE ip = $1 AND port = $2 AND name = $3 AND node_id = $4 AND change_key = $6`,
			o.IP, int32(o.Port), o.Name, o.NodeID, o.SeenAt, key)
		if err != nil || tag.RowsAffected() > 0 {
			return false, err
		}
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO observations (run_id, node_id, ip, port, name, protocol, status, first_seen_at, seen_at, cert_sha256, cert_names, raw, signature, search_text, change_key, seq)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10, $11, $12, $13, $14, nextval('observations_seq'))`,
		runID, o.NodeID, o.IP, int32(o.Port), o.Name, o.Protocol, o.Status, o.SeenAt, shaArg, names, []byte(o.Data), o.Signature, SearchText(o.Data, names), key)
	return err == nil, err
}

const obsColumns = `id, coalesce(run_id, 0), node_id, host(ip), port, name, protocol, status, coalesce(first_seen_at, seen_at), seen_at, coalesce(cert_sha256, ''), coalesce(cert_names, '{}'), raw, signature, coalesce(seq, id)`

func scanObservation(row pgx.Row) (client.Observation, error) {
	var o client.Observation
	var raw []byte
	err := row.Scan(&o.ID, &o.RunID, &o.NodeID, &o.IP, &o.Port, &o.Name, &o.Protocol, &o.Status, &o.FirstSeenAt, &o.SeenAt, &o.CertSHA256, &o.CertNames, &raw, &o.Signature, &o.Seq)
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
		add("search_text LIKE ?", "%"+escapeLike(strings.ToLower(q.Text))+"%")
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

// ErrSearchTimeout means a search ran past searchTimeout and was cancelled by Postgres.
var ErrSearchTimeout = errors.New("search timed out")

const searchTimeout = "5s"

func (s *Store) Search(ctx context.Context, q client.Query) (client.Page, error) {
	page, err := s.search(ctx, q)
	var pgErr *pgconn.PgError
	// 57014 is query_canceled - https://www.postgresql.org/docs/current/errcodes-appendix.html
	if errors.As(err, &pgErr) && pgErr.Code == "57014" && ctx.Err() == nil {
		return page, ErrSearchTimeout
	}
	return page, err
}

func (s *Store) search(ctx context.Context, q client.Query) (client.Page, error) {
	page := client.Page{Results: []client.Observation{}}
	sql, args, err := buildSearch(q)
	if err != nil {
		return page, fmt.Errorf("%w: %v", ErrBadQuery, err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return page, err
	}
	defer tx.Rollback(ctx)
	// Server side, so a slow search stops burning a small boid's disk even after the client gives up.
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '`+searchTimeout+`'`); err != nil {
		return page, err
	}
	rows, err := tx.Query(ctx, sql, args...)
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

// SearchTextPending counts observations stored before search_text existed.
func (s *Store) SearchTextPending(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM observations WHERE search_text IS NULL`).Scan(&n)
	return n, err
}

// BackfillSearchText fills search_text for older observations in small batches,
// so a small boid keeps serving while it runs. It returns the rows filled.
func (s *Store) BackfillSearchText(ctx context.Context) (int, error) {
	done := 0
	for {
		rows, err := s.pool.Query(ctx,
			`SELECT id, raw, coalesce(cert_names, '{}') FROM observations WHERE search_text IS NULL ORDER BY id LIMIT 500`)
		if err != nil {
			return done, err
		}
		b := &pgx.Batch{}
		for rows.Next() {
			var id int64
			var raw []byte
			var names []string
			if err := rows.Scan(&id, &raw, &names); err != nil {
				rows.Close()
				return done, err
			}
			b.Queue(`UPDATE observations SET search_text = $2 WHERE id = $1`, id, SearchText(raw, names))
		}
		if err := rows.Err(); err != nil {
			return done, err
		}
		if b.Len() == 0 {
			return done, nil
		}
		n, err := execBatch(ctx, s, b)
		done += n
		if err != nil {
			return done, err
		}
	}
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

// RangeExclusions holds the operator's exclusions without the opted-out addresses.
func (s *Store) RangeExclusions(ctx context.Context) (*netset.Set, error) {
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

// ExclusionSet holds the operator's exclusions and the opted-out addresses
// that overlap within, so a scan only carries the entries it can hit.
func (s *Store) ExclusionSet(ctx context.Context, within []netip.Prefix) (*netset.Set, error) {
	set := &netset.Set{}
	for _, w := range within {
		rows, err := s.pool.Query(ctx, `SELECT cidr FROM exclusions WHERE cidr && $1
			UNION ALL
			SELECT set_masklen(ip, 32) FROM (SELECT DISTINCT ON (ip) ip, action, expires_at FROM optouts
				WHERE ip <<= $1 ORDER BY ip, signed_at DESC, signature DESC) latest
			WHERE action = 'add' AND expires_at > now()`, w.Masked())
		if err != nil {
			return nil, err
		}
		prefixes, err := pgx.CollectRows(rows, pgx.RowTo[netip.Prefix])
		if err != nil {
			return nil, err
		}
		for _, p := range prefixes {
			set.Add(p)
		}
	}
	return set, nil
}

// PurgeRange deletes stored observations inside p.
func (s *Store) PurgeRange(ctx context.Context, p netip.Prefix) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM observations WHERE ip <<= $1`, p)
	return tag.RowsAffected(), err
}
