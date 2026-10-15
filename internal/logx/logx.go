// Package logx sets up two log outputs: short readable lines on the console
// for people watching a node, and an optional JSON lines file at debug level
// for later analysis.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

const LevelCritical = slog.Level(12)

var levels = []struct {
	name  string
	level slog.Level
}{
	{"DEBUG", slog.LevelDebug},
	{"INFO", slog.LevelInfo},
	{"WARNING", slog.LevelWarn},
	{"ERROR", slog.LevelError},
	{"CRITICAL", LevelCritical},
}

// Setup installs the default logger. node names the boid on every console line
// and in every debug file record, so files from several nodes can be merged.
func Setup(console io.Writer, level slog.Level, debugFile, node string) (func() error, error) {
	handlers := []slog.Handler{NewConsole(console, level, node)}
	closer := func() error { return nil }
	if debugFile != "" {
		f, err := os.OpenFile(debugFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		closer = f.Close
		h := slog.NewJSONHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: jsonLevel})
		handlers = append(handlers, h.WithAttrs([]slog.Attr{slog.String("node", node)}))
	}
	slog.SetDefault(slog.New(slog.NewMultiHandler(handlers...)))
	return closer, nil
}

func jsonLevel(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.LevelKey {
		if l, ok := a.Value.Any().(slog.Level); ok && l == LevelCritical {
			a.Value = slog.StringValue("CRITICAL")
		}
	}
	return a
}

// ParseLevel accepts DEBUG, INFO, WARNING (or WARN), ERROR and CRITICAL in any case.
func ParseLevel(s string) (slog.Level, error) {
	u := strings.ToUpper(strings.TrimSpace(s))
	if u == "WARN" {
		u = "WARNING"
	}
	names := make([]string, len(levels))
	for i, l := range levels {
		if l.name == u {
			return l.level, nil
		}
		names[i] = l.name
	}
	return 0, fmt.Errorf("unknown log level %q, want one of %s", s, strings.Join(names, ", "))
}

func levelName(l slog.Level) string {
	for i := len(levels) - 1; i > 0; i-- {
		if l >= levels[i].level {
			return levels[i].name
		}
	}
	return levels[0].name
}

// Console writes "2006-01-02 15:04:05 - wren: message" at INFO and
// "2006-01-02 15:04:05 - wren [warning]: message" at other levels. Fields
// follow as key=value only when the console is at DEBUG; otherwise only an
// "err" field is shown, appended to the message.
type Console struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Level
	name  string
	attrs []slog.Attr
}

func NewConsole(w io.Writer, level slog.Level, name string) *Console {
	return &Console{mu: &sync.Mutex{}, w: w, level: level, name: name}
}

func (c *Console) Enabled(_ context.Context, l slog.Level) bool { return l >= c.level }

func (c *Console) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Time.Format("2006-01-02 15:04:05"))
	b.WriteString(" - ")
	b.WriteString(c.name)
	if r.Level != slog.LevelInfo {
		b.WriteString(" [" + strings.ToLower(levelName(r.Level)) + "]")
	}
	b.WriteString(": ")
	b.WriteString(r.Message)
	verbose := c.level <= slog.LevelDebug
	each := func(a slog.Attr) bool {
		if verbose {
			writeAttr(&b, "", a)
		} else if a.Key == "err" {
			if v := a.Value.Resolve().String(); v != "" {
				b.WriteString(": " + v)
			}
		}
		return true
	}
	for _, a := range c.attrs {
		each(a)
	}
	r.Attrs(each)
	b.WriteByte('\n')
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := io.WriteString(c.w, b.String())
	return err
}

func (c *Console) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *c
	n.attrs = append(append([]slog.Attr(nil), c.attrs...), attrs...)
	return &n
}

// WithGroup is not used by boidscan; group names are dropped.
func (c *Console) WithGroup(string) slog.Handler { return c }

func writeAttr(b *strings.Builder, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		for _, g := range a.Value.Group() {
			writeAttr(b, prefix+a.Key+".", g)
		}
		return
	}
	v := a.Value.String()
	if v == "" || strings.ContainsAny(v, " \"=\n\t") {
		v = fmt.Sprintf("%q", v)
	}
	fmt.Fprintf(b, " %s%s=%s", prefix, a.Key, v)
}
