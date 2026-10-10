// Package grab collects banners and handshakes by running zgrab2 in "multiple" mode.
package grab

import (
	"bufio"
	"context"
	_ "embed"
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
	// Generic services run on every port without a specific service. Only
	// their successful results are kept, since most of them do not match.
	Generic bool
}

//go:embed ports.txt
var portsTxt string

// DefaultPorts is the port list scanned when none is given.
func DefaultPorts() []uint16 {
	var ports []uint16
	for _, line := range strings.Split(portsTxt, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, f := range strings.Split(line, ",") {
			if n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 16); err == nil && n > 0 {
				ports = append(ports, uint16(n))
			}
		}
	}
	return ports
}

// KnownServices only collect what a server volunteers during a normal
// handshake. Modules that support credentials are left at their no-auth defaults.
func KnownServices(userAgent string) []Service {
	ua := map[string]string{"user-agent": userAgent, "raw-headers": "true"}
	uaTLS := map[string]string{"user-agent": userAgent, "raw-headers": "true", "use-https": "true"}
	tls := func(flag string) map[string]string { return map[string]string{flag: "true"} }
	return []Service{
		{Name: "ftp21", Module: "ftp", Port: 21},
		{Name: "ssh22", Module: "ssh", Port: 22},
		{Name: "telnet23", Module: "telnet", Port: 23},
		{Name: "smtp25", Module: "smtp", Port: 25},
		{Name: "http80", Module: "http", Port: 80, Flags: ua},
		{Name: "siemens102", Module: "siemens", Port: 102},
		{Name: "pop3110", Module: "pop3", Port: 110},
		{Name: "imap143", Module: "imap", Port: 143},
		{Name: "https443", Module: "http", Port: 443, Flags: uaTLS},
		{Name: "smb445", Module: "smb", Port: 445},
		{Name: "smtps465", Module: "smtp", Port: 465, Flags: tls("smtps")},
		{Name: "modbus502", Module: "modbus", Port: 502},
		{Name: "smtp587", Module: "smtp", Port: 587},
		{Name: "ipp631", Module: "ipp", Port: 631},
		{Name: "ftps990", Module: "ftp", Port: 990, Flags: tls("implicit-tls")},
		{Name: "imaps993", Module: "imap", Port: 993, Flags: tls("imaps")},
		{Name: "pop3s995", Module: "pop3", Port: 995, Flags: tls("pop3s")},
		{Name: "socks51080", Module: "socks5", Port: 1080},
		{Name: "mssql1433", Module: "mssql", Port: 1433},
		{Name: "oracle1521", Module: "oracle", Port: 1521},
		{Name: "pptp1723", Module: "pptp", Port: 1723},
		{Name: "mqtt1883", Module: "mqtt", Port: 1883},
		{Name: "fox1911", Module: "fox", Port: 1911},
		{Name: "ssh2222", Module: "ssh", Port: 2222},
		{Name: "telnet2323", Module: "telnet", Port: 2323},
		{Name: "mysql3306", Module: "mysql", Port: 3306},
		{Name: "managesieve4190", Module: "managesieve", Port: 4190},
		{Name: "postgres5432", Module: "postgres", Port: 5432},
		{Name: "amqp5672", Module: "amqp091", Port: 5672},
		{Name: "redis6379", Module: "redis", Port: 6379},
		{Name: "http8080", Module: "http", Port: 8080, Flags: ua},
		{Name: "https8443", Module: "http", Port: 8443, Flags: uaTLS},
		{Name: "mqtts8883", Module: "mqtt", Port: 8883, Flags: tls("tls")},
		{Name: "memcached11211", Module: "memcached", Port: 11211},
		{Name: "dnp320000", Module: "dnp3", Port: 20000},
		{Name: "mongodb27017", Module: "mongodb", Port: 27017},
	}
}

// GenericServices cover server-first protocols (banner) and web servers on
// any port (http, falling back to HTTPS).
func GenericServices(userAgent string) []Service {
	return []Service{
		{Name: "banner", Module: "banner", Generic: true},
		{Name: "http", Module: "http", Generic: true, Flags: map[string]string{
			"user-agent": userAgent, "raw-headers": "true", "retry-https": "true", "fail-http-to-https": "true",
		}},
	}
}

// Plan decides which modules run on each discovered port.
type Plan struct {
	ports   []uint16
	known   map[uint16]Service
	generic []Service
}

func NewPlan(userAgent string, ports []uint16) *Plan {
	p := &Plan{ports: ports, known: map[uint16]Service{}}
	for _, s := range KnownServices(userAgent) {
		p.known[s.Port] = s
	}
	p.generic = GenericServices(userAgent)
	return p
}

func (p *Plan) Ports() []uint16 { return p.ports }

func (p *Plan) For(port uint16) []Service {
	if s, ok := p.known[port]; ok {
		return []Service{s}
	}
	return p.generic
}

// Services lists every module the plan can use, for the zgrab2 config.
func (p *Plan) Services() []Service {
	var out []Service
	needGeneric := false
	for _, port := range p.ports {
		if s, ok := p.known[port]; ok {
			out = append(out, s)
		} else {
			needGeneric = true
		}
	}
	if needGeneric {
		out = append(out, p.generic...)
	}
	return out
}

// INI renders the zgrab2 multiple-mode config.
func INI(services []Service) string {
	var b strings.Builder
	for _, s := range services {
		fmt.Fprintf(&b, "[%s]\ntrigger=%q\nname=%q\n", s.Module, s.Name, s.Name)
		if s.Port != 0 {
			fmt.Fprintf(&b, "port=%d\n", s.Port)
		}
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
		if svc.Generic && r.Status != "success" {
			continue
		}
		port := r.Port
		if port == 0 {
			port = svc.Port
		}
		if port == 0 {
			continue
		}
		obs = append(obs, Observation{IP: ip, Port: port, Name: name, Protocol: r.Protocol, Status: r.Status, Raw: raw})
	}
	return obs, nil
}

// Run feeds hits to zgrab2 and sends each result to out. It closes out when done.
func Run(ctx context.Context, binary string, plan *Plan, p *policy.Policy, blocklist string, hits <-chan discover.Hit, out chan<- Observation) error {
	defer close(out)
	services := plan.Services()
	byName := map[string]Service{}
	for _, s := range services {
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
			if !p.Allowed(h.IP) {
				slog.Warn("exclusion check rejected host before grab", "addr", h.IP)
				continue
			}
			for _, svc := range plan.For(h.Port) {
				if _, err := fmt.Fprintf(w, "%s,,%s,%s\n", h.IP, svc.Name, strconv.Itoa(int(h.Port))); err != nil {
					return
				}
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
