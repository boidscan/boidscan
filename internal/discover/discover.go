// Package discover finds open TCP ports by running zmap.
package discover

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/boidscan/boidscan/internal/policy"
)

type Hit struct {
	IP   netip.Addr
	Port uint16
}

type Options struct {
	Binary    string
	Targets   []netip.Prefix
	Ports     []uint16
	Blocklist string
	Rate      int
	Interface string
	// Gateway MAC, needed when zmap cannot detect it (common in containers).
	GatewayMAC string
	// IPLayer sends raw IP packets and lets the kernel handle L2.
	IPLayer bool
	// Cooldown in seconds; 0 keeps zmap's default of 8.
	Cooldown int
}

func Args(o Options) []string {
	ports := make([]string, len(o.Ports))
	for i, p := range o.Ports {
		ports[i] = strconv.Itoa(int(p))
	}
	args := []string{
		"--target-ports=" + strings.Join(ports, ","),
		"--rate=" + strconv.Itoa(o.Rate),
		"--blocklist-file=" + o.Blocklist,
		"--output-file=-",
		"--output-module=csv",
		"--output-fields=saddr,sport",
		"--output-filter=success = 1 && repeat = 0",
		"--quiet",
	}
	if o.Interface != "" {
		args = append(args, "--interface="+o.Interface)
	}
	if o.GatewayMAC != "" {
		args = append(args, "--gateway-mac="+o.GatewayMAC)
	}
	if o.IPLayer {
		args = append(args, "--iplayer")
	}
	if o.Cooldown > 0 {
		args = append(args, "--cooldown-time="+strconv.Itoa(o.Cooldown))
	}
	for _, t := range o.Targets {
		args = append(args, t.String())
	}
	return args
}

// Parse reads zmap CSV output. Hits outside the requested targets or ports, or
// rejected by the policy, are dropped.
func Parse(r io.Reader, o Options, p *policy.Policy, out chan<- Hit) error {
	wantPort := map[uint16]bool{}
	for _, port := range o.Ports {
		wantPort[port] = true
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line == "saddr,sport" {
			continue
		}
		addrStr, portStr, ok := strings.Cut(line, ",")
		if !ok {
			return fmt.Errorf("unexpected zmap output %q", line)
		}
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			return fmt.Errorf("unexpected zmap output %q: %w", line, err)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return fmt.Errorf("unexpected zmap output %q: %w", line, err)
		}
		if !wantPort[uint16(port)] || !inTargets(addr, o.Targets) || !p.Allowed(addr) {
			slog.Warn("dropping out-of-scope zmap result "+addr.String()+":"+portStr, "addr", addr, "port", port)
			continue
		}
		out <- Hit{IP: addr, Port: uint16(port)}
	}
	return sc.Err()
}

func inTargets(a netip.Addr, targets []netip.Prefix) bool {
	for _, t := range targets {
		if t.Contains(a) {
			return true
		}
	}
	return false
}

// Run starts zmap and sends every open port to out. It closes out when done.
func Run(ctx context.Context, o Options, p *policy.Policy, out chan<- Hit) error {
	defer close(out)
	if err := p.CheckTargets(o.Targets); err != nil {
		return err
	}
	if o.Rate <= 0 || o.Rate > p.Rate {
		o.Rate = p.Rate
	}
	cmd := exec.CommandContext(ctx, o.Binary, Args(o)...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting zmap: %w", err)
	}
	perr := Parse(stdout, o, p, out)
	if perr != nil {
		_ = cmd.Process.Kill()
		io.Copy(io.Discard, stdout)
	}
	werr := cmd.Wait()
	if perr != nil {
		return perr
	}
	if werr != nil {
		return fmt.Errorf("zmap: %w", werr)
	}
	return nil
}
