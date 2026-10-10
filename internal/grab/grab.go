// Package grab collects banners and handshakes by running zgrab2 in "multiple" mode.
package grab

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/boidscan/boidscan/internal/discover"
	"github.com/boidscan/boidscan/internal/policy"
)

// Service maps a port to a zgrab2 module. Name doubles as the zgrab2 trigger
// tag and the key under "data" in zgrab2 output.
type Service struct {
	Name   string
	Module string
	Port   uint16
	Flags  map[string]string
}

// DefaultServices only collects what a server volunteers during a normal
// handshake. Modules that support credentials are left at their no-auth defaults.
func DefaultServices(userAgent string) []Service {
	ua := map[string]string{"user-agent": userAgent, "raw-headers": "true"}
	uaTLS := map[string]string{"user-agent": userAgent, "raw-headers": "true", "use-https": "true"}
	return []Service{
		{"ftp21", "ftp", 21, nil},
		{"ssh22", "ssh", 22, nil},
		{"telnet23", "telnet", 23, nil},
		{"smtp25", "smtp", 25, nil},
		{"http80", "http", 80, ua},
		{"pop3110", "pop3", 110, nil},
		{"imap143", "imap", 143, nil},
		{"https443", "http", 443, uaTLS},
		{"mqtt1883", "mqtt", 1883, nil},
		{"mysql3306", "mysql", 3306, nil},
		{"postgres5432", "postgres", 5432, nil},
		{"redis6379", "redis", 6379, nil},
		{"http8080", "http", 8080, ua},
		{"https8443", "http", 8443, uaTLS},
		{"mongodb27017", "mongodb", 27017, nil},
	}
}

func Ports(services []Service) []uint16 {
	ports := make([]uint16, len(services))
	for i, s := range services {
		ports[i] = s.Port
	}
	return ports
}

// INI renders the zgrab2 multiple-mode config.
func INI(services []Service) string {
	var b strings.Builder
	for _, s := range services {
		fmt.Fprintf(&b, "[%s]\ntrigger=%q\nname=%q\nport=%d\n", s.Module, s.Name, s.Name, s.Port)
		keys := make([]string, 0, len(s.Flags))
		for k := range s.Flags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=%q\n", k, s.Flags[k])
		}
		b.WriteString("\n")
	}
	return b.String()
}

func Args(blocklist, iniPath string) []string {
	return []string{
		"--blocklist-file=" + blocklist,
		"--input-file=-",
		"--output-file=-",
		"--metadata-file=" + os.DevNull,
		"--status-updates-file=" + os.DevNull,
		"--flush",
		"multiple",
		"--config-file=" + iniPath,
	}
}

// Observation is one module result for one ip:port.
type Observation struct {
	IP       netip.Addr
	Port     uint16
	Name     string
	Protocol string
	Status   string
	// Raw is the zgrab2 ScanResponse for this module, unmodified.
	Raw json.RawMessage
}

type grabLine struct {
	IP   string                     `json:"ip"`
	Data map[string]json.RawMessage `json:"data"`
}

type scanResponse struct {
	Status   string `json:"status"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

// ParseLine splits one zgrab2 output line into observations.
func ParseLine(line []byte, byName map[string]Service) ([]Observation, error) {
	var g grabLine
	if err := json.Unmarshal(line, &g); err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(g.IP)
	if err != nil {
		return nil, fmt.Errorf("zgrab2 line without valid ip: %w", err)
	}
	var obs []Observation
	for name, raw := range g.Data {
		svc, ok := byName[name]
		if !ok {
			continue
		}
		var r scanResponse
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		port := r.Port
		if port == 0 {
			port = svc.Port
		}
		obs = append(obs, Observation{IP: ip, Port: port, Name: name, Protocol: r.Protocol, Status: r.Status, Raw: raw})
	}
	return obs, nil
}

// Run feeds hits to zgrab2 and sends each result to out. It closes out when done.
func Run(ctx context.Context, binary string, services []Service, p *policy.Policy, blocklist string, hits <-chan discover.Hit, out chan<- Observation) error {
	defer close(out)
	byPort := map[uint16]Service{}
	byName := map[string]Service{}
	for _, s := range services {
		byPort[s.Port] = s
		byName[s.Name] = s
	}

	ini, err := os.CreateTemp("", "boidscan-zgrab2-*.ini")
	if err != nil {
		return err
	}
	defer os.Remove(ini.Name())
	if _, err := ini.WriteString(INI(services)); err != nil {
		ini.Close()
		return err
	}
	if err := ini.Close(); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, binary, Args(blocklist, ini.Name())...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting zgrab2: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stdin.Close()
		w := bufio.NewWriter(stdin)
		defer w.Flush()
		for h := range hits {
			svc, ok := byPort[h.Port]
			if !ok {
				continue
			}
			if !p.Allowed(h.IP) {
				slog.Warn("opt-out check rejected host before grab", "addr", h.IP)
				continue
			}
			if _, err := fmt.Fprintf(w, "%s,,%s,%s\n", h.IP, svc.Name, strconv.Itoa(int(h.Port))); err != nil {
				return
			}
		}
	}()

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		obs, err := ParseLine(sc.Bytes(), byName)
		if err != nil {
			slog.Warn("skipping unparsable zgrab2 line", "err", err)
			continue
		}
		for _, o := range obs {
			out <- o
		}
	}
	serr := sc.Err()
	if serr != nil {
		io.Copy(io.Discard, stdout)
	}
	wg.Wait()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("zgrab2: %w", err)
	}
	return serr
}
