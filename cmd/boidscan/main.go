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
	"github.com/boidscan/boidscan/internal/grab"
	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/internal/policy"
	"github.com/boidscan/boidscan/internal/store"
)

const usage = `usage: boidscan <command> [flags]

commands:
  migrate                      create or upgrade the database schema
  scan [flags] CIDR...         discover and grab services, store the results
  serve [flags]                serve the info page with search, opt-out form and JSON API
  export ivre                  write HTTP results as zgrab2 JSON for "ivre scan2db"
  optout add|rm|list [CIDR]    manage the opt-out list without the form's size limit

Run "boidscan <command> -h" for flags. Flags default to BOIDSCAN_* environment variables.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmds := map[string]func(context.Context, []string) error{
		"migrate": cmdMigrate,
		"scan":    cmdScan,
		"serve":   cmdServe,
		"export":  cmdExport,
		"optout":  cmdOptOut,
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
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v, ok := os.LookupEnv("BOIDSCAN_" + name); ok {
		return v
	}
	return def
}

type common struct {
	dsn string
	id  policy.Identity
}

func (c *common) register(fs *flag.FlagSet, needIdentity bool) {
	fs.StringVar(&c.dsn, "db", env("DB", "postgres:///boidscan"), "PostgreSQL connection string")
	if needIdentity {
		fs.StringVar(&c.id.ProjectURL, "project-url", env("PROJECT_URL", "https://boidscan.network"), "URL explaining the project, shown to scanned hosts")
		fs.StringVar(&c.id.AbuseContact, "abuse-contact", env("ABUSE_CONTACT", ""), "abuse contact for this node")
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
	hostname, _ := os.Hostname()
	nodeID := fs.String("node-id", env("NODE_ID", hostname), "identifier recorded with every observation")
	rate := fs.Int("rate", 0, fmt.Sprintf("packets per second, at most %d (default %d)", policy.MaxRate, policy.MaxRate))
	ports := fs.String("ports", "", "ports or ranges to scan, e.g. 22,80,8000-8100 (default: Shodan's port list)")
	optoutFile := fs.String("optout-file", env("OPTOUT_FILE", ""), "extra opt-out list, one CIDR per line")
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

	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	optouts, err := st.OptOutSet(ctx)
	if err != nil {
		return fmt.Errorf("loading opt-outs: %w", err)
	}
	if *optoutFile != "" {
		f, err := os.Open(*optoutFile)
		if err != nil {
			return err
		}
		extra, err := netset.Read(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", *optoutFile, err)
		}
		optouts.AddSet(extra)
	}

	pol, err := policy.New(c.id, *rate, *lab, optouts)
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

	runID, err := st.StartRun(ctx, *nodeID, targets, plan.Ports())
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
		if err := st.AddObservation(ctx, runID, *nodeID, o); err != nil {
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.id.Validate(); err != nil {
		return err
	}
	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.New(st, c.id).Handler(),
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

func cmdOptOut(ctx context.Context, args []string) error {
	var c common
	fs := flag.NewFlagSet("optout", flag.ContinueOnError)
	c.register(fs, false)
	contact := fs.String("contact", "", "who requested the opt-out")
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
		list, err := st.OptOuts(ctx)
		if err != nil {
			return err
		}
		for _, o := range list {
			fmt.Printf("%s\t%s\n", o.CIDR, o.AddedAt.Format(time.RFC3339))
		}
		return nil
	case "add", "rm":
		p, err := netset.ParsePrefix(fs.Arg(1))
		if err != nil {
			return fmt.Errorf("cidr: %w", err)
		}
		if fs.Arg(0) == "rm" {
			ok, err := st.RemoveOptOut(ctx, p)
			if err == nil && !ok {
				err = fmt.Errorf("%s is not on the opt-out list", p)
			}
			return err
		}
		if err := st.AddOptOut(ctx, p, *contact); err != nil {
			return err
		}
		n, err := st.PurgeOptedOut(ctx, p)
		slog.Info("opt-out added", "prefix", p, "purged", n)
		return err
	default:
		return errors.New("usage: boidscan optout add|rm|list [CIDR]")
	}
}
