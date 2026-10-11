package scan

import (
	"context"
	"os"
	"slices"

	"github.com/boidscan/boidscan/internal/discover"
	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/grab"
	"github.com/boidscan/boidscan/internal/policy"
)

// Check grabs single targets with zgrab2 alone, to verify other boids'
// results. A target the policy does not allow is reported unavailable.
func Check(ctx context.Context, pol *policy.Policy, tools Tools, targets []fed.CheckTarget) ([]fed.CheckResult, error) {
	results := make([]fed.CheckResult, len(targets))
	type hostPort struct {
		ip   string
		port uint16
	}
	seen := map[hostPort]bool{}
	var ports []uint16
	hits := make(chan discover.Hit, len(targets))
	for i, t := range targets {
		if !pol.Allowed(t.IP) {
			results[i].Unavailable = true
			continue
		}
		if k := (hostPort{t.IP.String(), t.Port}); !seen[k] {
			seen[k] = true
			hits <- discover.Hit{IP: t.IP, Port: t.Port}
			if !slices.Contains(ports, t.Port) {
				ports = append(ports, t.Port)
			}
		}
	}
	close(hits)
	if len(ports) == 0 {
		return results, nil
	}
	blocklist, err := pol.WriteBlocklist()
	if err != nil {
		return nil, err
	}
	defer os.Remove(blocklist)
	obs := make(chan grab.Observation, 64)
	done := make(chan error, 1)
	go func() {
		done <- grab.Run(ctx, tools.ZGrab2, grab.NewPlan(pol.UserAgent(), ports), pol, blocklist, hits, obs)
	}()
	for o := range obs {
		for i, t := range targets {
			if t.IP == o.IP.Unmap() && t.Port == o.Port && t.Name == o.Name {
				results[i] = fed.CheckResult{Open: o.Status == "success", Fingerprint: grab.Fingerprint(o.Raw)}
			}
		}
	}
	return results, <-done
}
