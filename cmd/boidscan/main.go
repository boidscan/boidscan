package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/boidscan/boidscan/internal/api"
	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/export"
	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/grab"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/internal/logx"
	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/internal/policy"
	"github.com/boidscan/boidscan/internal/scan"
	"github.com/boidscan/boidscan/internal/store"
)

const usage = `usage: boidscan <command> [flags]

commands:
  migrate                      create or upgrade the database schema
  scan [flags] CIDR...         discover and grab services, store the results
  serve [flags]                serve the info page with search and the JSON API
  worker [flags]               take part in the flock's sweep: lease, scan, repeat
  export ivre                  write HTTP results as zgrab2 JSON for "ivre scan2db"
  exclude add|rm|list [CIDR]   manage ranges this node never scans

Run "boidscan <command> -h" for flags. Flags default to BOIDSCAN_* environment variables.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	level, err := logx.ParseLevel(env("LOG_LEVEL", "info"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "BOIDSCAN_LOG_LEVEL:", err)
		os.Exit(2)
	}
	hostname, _ := os.Hostname()
	closeLog, err := logx.Setup(os.Stderr, level, env("DEBUG_LOG", ""), env("NODE_NAME", hostname))
	if err != nil {
		fmt.Fprintln(os.Stderr, "BOIDSCAN_DEBUG_LOG:", err)
		os.Exit(2)
	}
	defer closeLog()

	cmds := map[string]func(context.Context, []string) error{
		"migrate": cmdMigrate,
		"scan":    cmdScan,
		"serve":   cmdServe,
		"worker":  cmdWorker,
		"export":  cmdExport,
		"exclude": cmdExclude,
	}
	run, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(ctx, os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		slog.Error(os.Args[1]+" failed", "err", err)
		closeLog()
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v, ok := os.LookupEnv("BOIDSCAN_" + name); ok {
		return v
	}
	return def
}

func envDuration(name string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(env(name, ""))
	if err != nil {
		return def
	}
	return d
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

type common struct {
	dsn     string
	id      policy.Identity
	keyFile string
}

func (c *common) register(fs *flag.FlagSet, needIdentity bool) {
	fs.StringVar(&c.dsn, "db", env("DB", "postgres:///boidscan"), "PostgreSQL connection string")
	if needIdentity {
		fs.StringVar(&c.id.ProjectURL, "project-url", env("PROJECT_URL", "https://boidscan.network"), "URL explaining the project, shown to scanned hosts")
		fs.StringVar(&c.id.AbuseContact, "abuse-contact", env("ABUSE_CONTACT", ""), "abuse contact for this node")
		fs.StringVar(&c.keyFile, "key-file", env("KEY_FILE", "boidscan.key"), "node key; created on first start. Its public half is the node ID")
	}
}

func (c *common) open(ctx context.Context) (*store.Store, error) {
	st, err := store.Open(ctx, c.dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	return st, nil
}

func cmdMigrate(ctx context.Context, args []string) error {
	var c common
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	c.register(fs, false)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	return st.Migrate(ctx)
}

// parsePorts reads a list like "22,80,8000-8100". An empty list means the defaults.
func parsePorts(s string) ([]uint16, error) {
	if s == "" {
		return grab.DefaultPorts(), nil
	}
	seen := map[uint16]bool{}
	var out []uint16
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		if !isRange {
			hi = lo
		}
		from, err1 := strconv.ParseUint(lo, 10, 16)
		to, err2 := strconv.ParseUint(hi, 10, 16)
		if err1 != nil || err2 != nil || from == 0 || to < from {
			return nil, fmt.Errorf("port %q: want a number or range between 1 and 65535", part)
		}
		for n := from; n <= to; n++ {
			if !seen[uint16(n)] {
				seen[uint16(n)] = true
				out = append(out, uint16(n))
			}
		}
	}
	return out, nil
}

// scanFlags are shared by scan and worker.
type scanFlags struct {
	rate        int
	excludeFile string
	tools       scan.Tools
}

func (f *scanFlags) register(fs *flag.FlagSet) {
	fs.IntVar(&f.rate, "rate", 0, fmt.Sprintf("packets per second, at most %d (default %d)", policy.MaxRate, policy.MaxRate))
	fs.StringVar(&f.excludeFile, "exclude-file", env("EXCLUDE_FILE", ""), "extra ranges not to scan, one CIDR per line")
	fs.StringVar(&f.tools.ZMap, "zmap", env("ZMAP", "zmap"), "zmap binary")
	fs.StringVar(&f.tools.ZGrab2, "zgrab2", env("ZGRAB2", "zgrab2"), "zgrab2 binary")
	fs.StringVar(&f.tools.Interface, "interface", env("INTERFACE", ""), "network interface for zmap")
	fs.StringVar(&f.tools.GatewayMAC, "gateway-mac", env("GATEWAY_MAC", ""), "gateway MAC for zmap")
	fs.BoolVar(&f.tools.IPLayer, "ip-layer", env("IP_LAYER", "") == "true", "send IP packets without Ethernet framing (zmap --iplayer), e.g. on VPNs or container bridges")
	fs.IntVar(&f.tools.Cooldown, "cooldown", 0, "seconds zmap waits for late replies (default: zmap's 8)")
}

// policy loads the exclusions afresh, so ranges added while a worker runs apply to its next unit.
func (f *scanFlags) policy(ctx context.Context, st *store.Store, id policy.Identity, lab bool) (*policy.Policy, error) {
	exclusions, err := st.ExclusionSet(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading exclusions: %w", err)
	}
	if f.excludeFile != "" {
		file, err := os.Open(f.excludeFile)
		if err != nil {
			return nil, err
		}
		extra, err := netset.Read(file)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.excludeFile, err)
		}
		exclusions.AddSet(extra)
	}
	return policy.New(id, f.rate, lab, exclusions)
}

func cmdScan(ctx context.Context, args []string) error {
	var c common
	var sf scanFlags
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	c.register(fs, true)
	sf.register(fs)
	ports := fs.String("ports", "", "ports or ranges to scan, e.g. 22,80,8000-8100 (default: Shodan's port list)")
	lab := fs.Bool("lab", false, "allow RFC 1918 targets, and only those, for testing on your own network")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var targets []netip.Prefix
	for _, a := range fs.Args() {
		p, err := netset.ParsePrefix(a)
		if err != nil {
			return fmt.Errorf("target %q: %w", a, err)
		}
		targets = append(targets, p)
	}
	portList, err := parsePorts(*ports)
	if err != nil {
		return err
	}

	key, err := identity.Load(c.keyFile)
	if err != nil {
		return fmt.Errorf("node key: %w", err)
	}
	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	pol, err := sf.policy(ctx, st, c.id, *lab)
	if err != nil {
		return err
	}
	_, err = scan.Run(ctx, st, key, pol, sf.tools, scan.Job{Targets: targets, Ports: portList})
	return err
}

// flockFlags are shared by serve and worker; boids only cooperate when they match.
type flockFlags struct {
	name      string
	endpoint  string
	lab       bool
	labRange  string
	minRescan time.Duration
}

func (f *flockFlags) register(fs *flag.FlagSet) {
	hostname, _ := os.Hostname()
	fs.StringVar(&f.name, "name", env("NODE_NAME", hostname), "name shown to other boids, up to 32 characters")
	fs.StringVar(&f.endpoint, "endpoint", env("ENDPOINT", ""), "http://<public IPv4> where other boids reach this node; empty disables federation")
	fs.BoolVar(&f.lab, "lab", env("LAB", "") == "true", "lab flock: RFC 1918 endpoints and targets, and the lab catalog")
	fs.StringVar(&f.labRange, "lab-range", env("LAB_RANGE", ""), "the range a lab flock sweeps, e.g. 172.30.0.0/26")
	fs.DurationVar(&f.minRescan, "min-rescan", envDuration("MIN_RESCAN", 7*24*time.Hour), "the flock scans each block and port group at most this often")
}

func (f *flockFlags) catalog() (catalog.Catalog, error) {
	if !f.lab {
		return catalog.Default(), nil
	}
	p, err := netip.ParsePrefix(f.labRange)
	if err != nil {
		return catalog.Catalog{}, fmt.Errorf("lab mode needs -lab-range: %w", err)
	}
	return catalog.Lab(p)
}

func cmdWorker(ctx context.Context, args []string) error {
	var c common
	var sf scanFlags
	var ff flockFlags
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	c.register(fs, true)
	sf.register(fs)
	ff.register(fs)
	idle := fs.Duration("idle", envDuration("IDLE", time.Minute), "wait between rounds that found nothing to scan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if ff.endpoint == "" {
		return errors.New("worker needs the endpoint of this node's serve process (BOIDSCAN_ENDPOINT)")
	}
	if err := c.id.Validate(); err != nil {
		return err
	}
	cat, err := ff.catalog()
	if err != nil {
		return err
	}
	key, err := identity.Load(c.keyFile)
	if err != nil {
		return fmt.Errorf("node key: %w", err)
	}
	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	sw := fed.NewSweeper(fed.SweepConfig{
		Key:          key,
		Name:         ff.name,
		Endpoint:     ff.endpoint,
		Catalog:      cat,
		AllowPrivate: ff.lab,
		MinRescan:    ff.minRescan,
		Idle:         *idle,
		Scan: func(ctx context.Context, u catalog.Unit) error {
			pol, err := sf.policy(ctx, st, c.id, ff.lab)
			if err != nil {
				return err
			}
			_, err = scan.Run(ctx, st, key, pol, sf.tools, scan.Job{Targets: []netip.Prefix{u.Block}, Ports: cat.Ports(u.Group), Unit: &u})
			return err
		},
	}, st)
	slog.Info("sweeping with catalog "+cat.Name, "id", key.ID(), "min_rescan", ff.minRescan.String())
	sw.Run(ctx)
	return nil
}

func cmdServe(ctx context.Context, args []string) error {
	var c common
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	c.register(fs, true)
	var ff flockFlags
	ff.register(fs)
	listen := fs.String("listen", env("LISTEN", ":80"), "listen address; scanned hosts expect the info page on port 80")
	seeds := fs.String("seeds", env("SEEDS", ""), "comma-separated boid URLs or DNS names whose A records are boids")
	interval := fs.Duration("gossip-interval", envDuration("GOSSIP_INTERVAL", 30*time.Second), "time between gossip rounds")
	leaseTTL := fs.Duration("lease-ttl", envDuration("LEASE_TTL", 10*time.Minute), "how long a lease this node grants lasts without renewal")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.id.Validate(); err != nil {
		return err
	}
	cat, err := ff.catalog()
	if err != nil {
		return err
	}
	key, err := identity.Load(c.keyFile)
	if err != nil {
		return fmt.Errorf("node key: %w", err)
	}
	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	site := api.New(st, c.id)
	mux := http.NewServeMux()
	mux.Handle("/", site.Handler())
	if ff.endpoint != "" {
		node, err := fed.New(fed.Config{
			Key:          key,
			Name:         ff.name,
			Endpoint:     ff.endpoint,
			Contact:      c.id.AbuseContact,
			ProjectURL:   c.id.ProjectURL,
			Version:      policy.Version,
			Seeds:        splitList(*seeds),
			Interval:     *interval,
			AllowPrivate: ff.lab,
			Catalog:      cat,
			Data:         st,
			MinRescan:    ff.minRescan,
			LeaseTTL:     *leaseTTL,
		}, st)
		if err != nil {
			return err
		}
		site.SetFlock(node)
		mux.Handle("/fed/", node.Handler())
		go node.Run(ctx)
	} else {
		slog.Info("federation disabled: no endpoint configured", "id", key.ID())
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	slog.Info("serving", "addr", *listen)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func cmdExport(ctx context.Context, args []string) error {
	var c common
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	c.register(fs, false)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.Arg(0) != "ivre" {
		return errors.New(`only "export ivre" is supported`)
	}
	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	n, err := export.IVRE(ctx, st, os.Stdout)
	slog.Info("exported", "records", n)
	return err
}

func cmdExclude(ctx context.Context, args []string) error {
	var c common
	fs := flag.NewFlagSet("exclude", flag.ContinueOnError)
	c.register(fs, false)
	note := fs.String("note", "", "why the range is excluded, for the operator's own records")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	switch fs.Arg(0) {
	case "list":
		list, err := st.Exclusions(ctx)
		if err != nil {
			return err
		}
		for _, e := range list {
			fmt.Printf("%s\t%s\t%s\n", e.Prefix, e.AddedAt.Format(time.RFC3339), e.Note)
		}
		return nil
	case "add", "rm":
		p, err := netset.ParsePrefix(fs.Arg(1))
		if err != nil {
			return fmt.Errorf("cidr: %w", err)
		}
		if fs.Arg(0) == "rm" {
			ok, err := st.RemoveExclusion(ctx, p)
			if err == nil && !ok {
				err = fmt.Errorf("%s is not excluded", p)
			}
			return err
		}
		if err := st.AddExclusion(ctx, p, *note); err != nil {
			return err
		}
		n, err := st.PurgeRange(ctx, p)
		slog.Info("exclusion added; stored results in the range deleted", "prefix", p, "purged", n)
		return err
	default:
		return errors.New("usage: boidscan exclude add|rm|list [CIDR]")
	}
}
