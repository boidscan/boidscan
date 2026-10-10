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
	"time"
)

// Setup installs the default logger. node is added to every debug file record
// so files from several nodes can be merged.
func Setup(console io.Writer, level slog.Level, debugFile, node string) (func() error, error) {
	handlers := []slog.Handler{NewConsole(console, level)}
	closer := func() error { return nil }
	if debugFile != "" {
		f, err := os.OpenFile(debugFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		closer = f.Close
		h := slog.NewJSONHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug})
		handlers = append(handlers, h.WithAttrs([]slog.Attr{slog.String("node", node)}))
	}
	slog.SetDefault(slog.New(slog.NewMultiHandler(handlers...)))
	return closer, nil
}

func ParseLevel(s string) (slog.Level, error) {
	var l slog.Level
	err := l.UnmarshalText([]byte(s))
	return l, err
}

// Console writes "15:04:05 WARN  message key=value".
type Console struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Level
	attrs string
}

func NewConsole(w io.Writer, level slog.Level) *Console {
	return &Console{mu: &sync.Mutex{}, w: w, level: level}
}

func (c *Console) Enabled(_ context.Context, l slog.Level) bool { return l >= c.level }

func (c *Console) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Time.Format(time.TimeOnly))
	b.WriteByte(' ')
	fmt.Fprintf(&b, "%-5s ", r.Level.String())
	b.WriteString(r.Message)
	b.WriteString(c.attrs)
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, "", a)
		return true
	})
	b.WriteByte('\n')
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := io.WriteString(c.w, b.String())
	return err
}

func (c *Console) WithAttrs(attrs []slog.Attr) slog.Handler {
	var b strings.Builder
	for _, a := range attrs {
		writeAttr(&b, "", a)
	}
	n := *c
	n.attrs += b.String()
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
