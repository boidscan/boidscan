// Package scan runs one discovery and grab pass and stores its results.
package scan

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/discover"
	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/grab"
	"github.com/boidscan/boidscan/internal/policy"
	"github.com/boidscan/boidscan/internal/store"
)

type Tools struct {
	ZMap       string
	ZGrab2     string
	Interface  string
	GatewayMAC string
	IPLayer    bool
	// Cooldown is how long zmap waits for late replies, in seconds; 0 keeps zmap's default.
	Cooldown int
}

type Job struct {
	Targets []netip.Prefix
	Ports   []uint16
	// Unit is set for sweep scans.
	Unit *catalog.Unit
}

type Result struct {
	RunID   int64
	Stored  int
	Success int
}

func Run(ctx context.Context, st *store.Store, key fed.Signer, pol *policy.Policy, tools Tools, job Job) (Result, error) {
	var res Result
	if err := pol.CheckTargets(job.Targets); err != nil {
		return res, err
	}
	plan := grab.NewPlan(pol.UserAgent(), job.Ports)
	blocklist, err := pol.WriteBlocklist()
	if err != nil {
		return res, err
	}
	defer os.Remove(blocklist)

	res.RunID, err = st.StartRun(ctx, key.ID(), job.Targets, plan.Ports(), job.Unit)
	if err != nil {
		return res, err
	}
	slog.Info("scan started", "run", res.RunID, "targets", job.Targets, "ports", len(plan.Ports()), "rate", pol.Rate)

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	hits := make(chan discover.Hit, 1024)
	obs := make(chan grab.Observation, 1024)
	discErr := make(chan error, 1)
	grabErr := make(chan error, 1)
	go func() {
		discErr <- discover.Run(scanCtx, discover.Options{
			Binary:     tools.ZMap,
			Targets:    job.Targets,
			Ports:      plan.Ports(),
			Blocklist:  blocklist,
			Rate:       pol.Rate,
			Interface:  tools.Interface,
			GatewayMAC: tools.GatewayMAC,
			IPLayer:    tools.IPLayer,
			Cooldown:   tools.Cooldown,
		}, pol, hits)
	}()
	go func() {
		grabErr <- grab.Run(scanCtx, tools.ZGrab2, plan, pol, blocklist, hits, obs)
	}()

	var storeErr error
	for o := range obs {
		if storeErr != nil {
			continue
		}
		if err := st.AddObservation(ctx, res.RunID, key, o); err != nil {
			storeErr = err
			cancel()
			continue
		}
		res.Stored++
		if o.Status == "success" {
			res.Success++
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
	if err := st.FinishRun(finishCtx, res.RunID, runErr); err != nil {
		slog.Error("recording run result", "err", err)
	}
	slog.Info("scan finished", "run", res.RunID, "observations", res.Stored, "successful", res.Success)
	return res, runErr
}
