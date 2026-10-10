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
	"github.com/boidscan/boidscan/internal/discover"
	"github.com/boidscan/boidscan/internal/export"
	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/grab"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/internal/logx"
	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/internal/policy"
	"github.com/boidscan/boidscan/internal/store"
)

const usage = `usage: boidscan <command> [flags]

commands:
  migrate                      create or upgrade the database schema
  scan [flags] CIDR...         discover and grab services, store the results
  serve [flags]                serve the info page with search and the JSON API
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

func cmdScan(ctx context.Context, args []string) error {
	var c common
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	c.register(fs, true)
	rate := fs.Int("rate", 0, fmt.Sprintf("packets per second, at most %d (default %d)", policy.MaxRate, policy.MaxRate))
	ports := fs.String("ports", "", "ports or ranges to scan, e.g. 22,80,8000-8100 (default: Shodan's port list)")
	excludeFile := fs.String("exclude-file", env("EXCLUDE_FILE", ""), "extra ranges not to scan, one CIDR per line")
	lab := fs.Bool("lab", false, "allow RFC 1918 targets, and only those, for testing on your own network")
	zmapBin := fs.String("zmap", env("ZMAP", "zmap"), "zmap binary")
	zgrabBin := fs.String("zgrab2", env("ZGRAB2", "zgrab2"), "zgrab2 binary")
	iface := fs.String("interface", env("INTERFACE", ""), "network interface for zmap")
	gwMAC := fs.String("gateway-mac", env("GATEWAY_MAC", ""), "gateway MAC for zmap")
	ipLayer := fs.Bool("ip-layer", env("IP_LAYER", "") == "true", "send IP packets without Ethernet framing (zmap --iplayer), e.g. on VPNs or container bridges")
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

	key, err := identity.Load(c.keyFile)
	if err != nil {
		return fmt.Errorf("node key: %w", err)
	}
	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	exclusions, err := st.ExclusionSet(ctx)
	if err != nil {
		return fmt.Errorf("loading exclusions: %w", err)
	}
	if *excludeFile != "" {
		f, err := os.Open(*excludeFile)
		if err != nil {
			return err
		}
		extra, err := netset.Read(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", *excludeFile, err)
		}
		exclusions.AddSet(extra)
	}

	pol, err := policy.New(c.id, *rate, *lab, exclusions)
	if err != nil {
		return err
	}
	if err := pol.CheckTargets(targets); err != nil {
		return err
	}
	portList, err := parsePorts(*ports)
	if err != nil {
		return err
	}
	plan := grab.NewPlan(pol.UserAgent(), portList)
	blocklist, err := pol.WriteBlocklist()
	if err != nil {
		return err
	}
	defer os.Remove(blocklist)

	runID, err := st.StartRun(ctx, key.ID(), targets, plan.Ports())
	if err != nil {
		return err
	}
	slog.Info("scan started", "run", runID, "targets", targets, "ports", len(plan.Ports()), "rate", pol.Rate)

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	hits := make(chan discover.Hit, 1024)
	obs := make(chan grab.Observation, 1024)
	discErr := make(chan error, 1)
	grabErr := make(chan error, 1)
	go func() {
		discErr <- discover.Run(scanCtx, discover.Options{
			Binary:     *zmapBin,
			Targets:    targets,
			Ports:      plan.Ports(),
			Blocklist:  blocklist,
			Rate:       pol.Rate,
			Interface:  *iface,
			GatewayMAC: *gwMAC,
			IPLayer:    *ipLayer,
		}, pol, hits)
	}()
	go func() {
		grabErr <- grab.Run(scanCtx, *zgrabBin, plan, pol, blocklist, hits, obs)
	}()

	var stored, success int
	var storeErr error
	for o := range obs {
		if storeErr != nil {
			continue
		}
		if err := st.AddObservation(ctx, runID, key, o); err != nil {
			storeErr = err
			cancel()
			continue
		}
		stored++
		if o.Status == "success" {
			success++
		}
	}
	// If zgrab2 stopped early, zmap is still writing hits; stop it and unblock it.
	cancel()
	go func() {
		for range hits {
		}
	}()
	runErr := errors.Join(<-discErr, <-grabErr, storeErr)
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer finishCancel()
	if err := st.FinishRun(finishCtx, runID, runErr); err != nil {
		slog.Error("recording run result", "err", err)
	}
	slog.Info("scan finished", "run", runID, "observations", stored, "successful", success)
	return runErr
}

func cmdServe(ctx context.Context, args []string) error {
	var c common
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	c.register(fs, true)
	listen := fs.String("listen", env("LISTEN", ":80"), "listen address; scanned hosts expect the info page on port 80")
	hostname, _ := os.Hostname()
	name := fs.String("name", env("NODE_NAME", hostname), "name shown to other boids, up to 32 characters")
	endpoint := fs.String("endpoint", env("ENDPOINT", ""), "http://<public IPv4> where other boids reach this node; empty disables federation")
	seeds := fs.String("seeds", env("SEEDS", ""), "comma-separated boid URLs or DNS names whose A records are boids")
	interval := fs.Duration("gossip-interval", envDuration("GOSSIP_INTERVAL", 30*time.Second), "time between gossip rounds")
	lab := fs.Bool("lab", env("LAB", "") == "true", "accept RFC 1918 endpoints, for testing on your own network")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.id.Validate(); err != nil {
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
	if *endpoint != "" {
		node, err := fed.New(fed.Config{
			Key:          key,
			Name:         *name,
			Endpoint:     *endpoint,
			Contact:      c.id.AbuseContact,
			ProjectURL:   c.id.ProjectURL,
			Version:      policy.Version,
			Seeds:        splitList(*seeds),
			Interval:     *interval,
			AllowPrivate: *lab,
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
