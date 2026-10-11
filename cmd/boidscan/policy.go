package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/boidscan/boidscan/internal/flockpolicy"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/internal/policy"
	"github.com/boidscan/boidscan/pkg/sig"
)

const policyUsage = `usage: boidscan policy <command> [flags]

Maintainers, offline:
  keygen -out FILE                  create a maintainer key and print its ID
  new -out FILE [-from FILE]        write an unsigned policy for this build's catalog;
                                    with -from, the next serial of that policy
  sign -key FILE POLICY             add this key's signature to a policy or pause
  pause -key FILE -serial N -out F  sign an emergency pause of the policy with serial N
  verify POLICY...                  check signatures, from the trust root through each file
  bundle POLICY... > policy.json    verify, then write the file boids fetch from the policy URL

Operators:
  install FILE|-                    verify a policy, pause or bundle and store it; gossip spreads it
  show                              the policy this boid holds and whether it may sweep
`

func cmdPolicy(ctx context.Context, args []string) error {
	cmds := map[string]func(context.Context, []string) error{
		"keygen":  cmdPolicyKeygen,
		"new":     cmdPolicyNew,
		"sign":    cmdPolicySign,
		"pause":   cmdPolicyPause,
		"verify":  cmdPolicyVerify,
		"bundle":  cmdPolicyBundle,
		"install": cmdPolicyInstall,
		"show":    cmdPolicyShow,
	}
	if len(args) == 0 || cmds[args[0]] == nil {
		fmt.Fprint(os.Stderr, policyUsage)
		return flag.ErrHelp
	}
	return cmds[args[0]](ctx, args[1:])
}

func readDocument(path string) (flockpolicy.Document, error) {
	var d flockpolicy.Document
	b, err := os.ReadFile(path)
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func cmdPolicyKeygen(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("policy keygen", flag.ContinueOnError)
	out := fs.String("out", "", "where to write the private key; keep it offline")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	if _, err := os.Stat(*out); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s exists; not overwriting a key", *out)
	}
	k, err := identity.Load(*out)
	if err != nil {
		return err
	}
	fmt.Println(k.ID())
	return nil
}

func cmdPolicyNew(_ context.Context, args []string) error {
	var ff flockFlags
	fs := flag.NewFlagSet("policy new", flag.ContinueOnError)
	ff.register(fs)
	out := fs.String("out", "", "where to write the policy")
	from := fs.String("from", "", "previous policy; the new one takes its content and the next serial")
	valid := fs.Duration("for", flockpolicy.DefaultLifetime, "how long the policy is valid")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	cat, err := ff.catalog()
	if err != nil {
		return err
	}
	b := flockpolicy.Body{
		MaxRatePPS:   policy.MaxRate,
		MinRescan:    flockpolicy.Duration(7 * 24 * time.Hour),
		BumpInterval: flockpolicy.Duration(24 * time.Hour),
		RevokedNodes: []flockpolicy.Revoked{},
		Seeds:        []string{},
	}
	if *from != "" {
		d, err := readDocument(*from)
		if err != nil {
			return err
		}
		prev, err := flockpolicy.Parse(d)
		if err != nil {
			return err
		}
		b = prev.Body
	} else if b.Maintainers, err = ff.maintainers(); err != nil {
		return err
	}
	if len(b.Maintainers.Keys) == 0 {
		return errors.New("no maintainer keys: pass -policy-root or -from")
	}
	if b.Catalog != "" && b.Catalog != cat.Hash() {
		fmt.Fprintf(os.Stderr, "catalog changes from %s to %s (%s)\n", sig.Short(b.Catalog), sig.Short(cat.Hash()), cat.Name)
	}
	b.Serial++
	b.Catalog = cat.Hash()
	b.Issued = time.Now().UTC().Truncate(time.Second)
	b.Expires = b.Issued.Add(*valid)
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	d := flockpolicy.Document{Policy: raw, Signatures: []flockpolicy.Signature{}}
	if _, err := flockpolicy.Parse(d); err != nil {
		return err
	}
	if err := writeJSONFile(*out, d); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote policy %d to %s, valid until %s; edit it, then sign it\n", b.Serial, *out, sig.Time(b.Expires))
	return nil
}

func cmdPolicySign(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("policy sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "maintainer key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || fs.NArg() != 1 {
		return errors.New("usage: boidscan policy sign -key FILE POLICY")
	}
	if _, err := os.Stat(*keyFile); err != nil {
		return err
	}
	key, err := identity.Load(*keyFile)
	if err != nil {
		return err
	}
	path := fs.Arg(0)
	d, err := readDocument(path)
	if err != nil {
		return err
	}
	if d.Pause != nil {
		_, err = flockpolicy.ParsePause(d)
	} else {
		_, err = flockpolicy.Parse(d)
	}
	if err != nil {
		return err
	}
	for _, k := range d.DropInvalid() {
		fmt.Fprintf(os.Stderr, "dropped the signature of %s: the document changed after it signed\n", sig.Short(k))
	}
	d.Sign(key)
	if err := writeJSONFile(path, d); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "signed %s as %s; %d signatures\n", path, key.ID(), len(d.Signatures))
	return nil
}

func cmdPolicyPause(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("policy pause", flag.ContinueOnError)
	keyFile := fs.String("key", "", "maintainer key")
	serial := fs.Uint64("serial", 0, "serial of the policy in force")
	valid := fs.Duration("for", flockpolicy.MaxPause, "how long the pause lasts, at most 48h")
	out := fs.String("out", "", "where to write the pause")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *serial == 0 || *out == "" {
		return errors.New("usage: boidscan policy pause -key FILE -serial N -out FILE")
	}
	if _, err := os.Stat(*keyFile); err != nil {
		return err
	}
	key, err := identity.Load(*keyFile)
	if err != nil {
		return err
	}
	issued := time.Now().UTC().Truncate(time.Second)
	raw, err := json.Marshal(flockpolicy.PauseBody{Serial: *serial, Issued: issued, Expires: issued.Add(*valid)})
	if err != nil {
		return err
	}
	d := flockpolicy.Document{Pause: raw}
	if _, err := flockpolicy.ParsePause(d); err != nil {
		return err
	}
	d.Sign(key)
	return writeJSONFile(*out, d)
}

func cmdPolicyVerify(_ context.Context, args []string) error {
	var rf rootFlag
	fs := flag.NewFlagSet("policy verify", flag.ContinueOnError)
	rf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: boidscan policy verify POLICY...")
	}
	root, err := rf.maintainers()
	if err != nil {
		return err
	}
	_, _, err = verifyChain(root, fs.Args(), os.Stdout)
	return err
}

// cmdPolicyBundle writes what boids fetch from the policy URL: the policies
// that changed the maintainers, the newest one, and its emergency pause if
// one of the files is that pause.
func cmdPolicyBundle(_ context.Context, args []string) error {
	var rf rootFlag
	fs := flag.NewFlagSet("policy bundle", flag.ContinueOnError)
	rf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: boidscan policy bundle POLICY... > policy.json")
	}
	root, err := rf.maintainers()
	if err != nil {
		return err
	}
	st, policies, err := verifyChain(root, fs.Args(), os.Stderr)
	if err != nil {
		return err
	}
	b := flockpolicy.Bundle{Chain: flockpolicy.Chain(policies, 0)}
	if st.Pause != nil {
		b.Pause = &st.Pause.Doc
	}
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(out))
	return err
}

// verifyChain checks the files from the trust root on, as a boid would
// receive them: policies by serial, then emergency pauses.
func verifyChain(root flockpolicy.Maintainers, paths []string, report io.Writer) (flockpolicy.State, []flockpolicy.Policy, error) {
	type file struct {
		path   string
		doc    flockpolicy.Document
		serial uint64
	}
	var policies, pauses []file
	for _, path := range paths {
		d, err := readDocument(path)
		if err != nil {
			return flockpolicy.State{}, nil, err
		}
		if d.Pause != nil {
			pauses = append(pauses, file{path: path, doc: d})
			continue
		}
		p, err := flockpolicy.Parse(d)
		if err != nil {
			return flockpolicy.State{}, nil, fmt.Errorf("%s: %w", path, err)
		}
		policies = append(policies, file{path, d, p.Serial})
	}
	slices.SortFunc(policies, func(a, b file) int { return cmp.Compare(a.serial, b.serial) })

	now := time.Now()
	var st flockpolicy.State
	var accepted []flockpolicy.Policy
	for _, f := range policies {
		set := st.Maintainers(root)
		p, err := st.Accept(root, f.doc, now)
		if err != nil {
			return st, nil, fmt.Errorf("%s: %w", f.path, err)
		}
		st.Latest = &p
		accepted = append(accepted, p)
		state := "valid until " + sig.Time(p.Expires)
		if !now.Before(p.Expires) {
			state = "expired at " + sig.Time(p.Expires)
		}
		fmt.Fprintf(report, "%s: policy %d, %s, signed by %s (%d needed)\n", f.path, p.Serial, state, shortIDs(f.doc.SignedBy(set)), set.Threshold)
		if !p.Maintainers.Equal(set) {
			fmt.Fprintf(report, "%s: maintainers change to %s\n", f.path, p.Maintainers)
		}
	}
	for _, f := range pauses {
		p, err := st.AcceptPause(f.doc, now)
		if err != nil {
			return st, nil, fmt.Errorf("%s: %w", f.path, err)
		}
		st.Pause = &p
		fmt.Fprintf(report, "%s: emergency pause of policy %d until %s, signed by %s\n", f.path, p.Serial, sig.Time(p.Expires), shortIDs(f.doc.SignedBy(st.Latest.Maintainers)))
	}
	return st, accepted, nil
}

func shortIDs(ids []string) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = sig.Short(id)
	}
	return strings.Join(out, ", ")
}

// readBundle accepts a bundle, a single policy or a single emergency pause.
func readBundle(path string) (flockpolicy.Bundle, error) {
	var b flockpolicy.Bundle
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return b, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return b, fmt.Errorf("%s: %w", path, err)
	}
	if _, ok := probe["chain"]; ok {
		return b, json.Unmarshal(raw, &b)
	}
	var d flockpolicy.Document
	if err := json.Unmarshal(raw, &d); err != nil {
		return b, fmt.Errorf("%s: %w", path, err)
	}
	if d.Pause != nil {
		b.Pause = &d
	} else {
		b.Chain = []flockpolicy.Document{d}
	}
	return b, nil
}

func cmdPolicyInstall(ctx context.Context, args []string) error {
	var c common
	var rf rootFlag
	fs := flag.NewFlagSet("policy install", flag.ContinueOnError)
	c.register(fs, false)
	rf.register(fs)
	keyFile := fs.String("key-file", env("KEY_FILE", "boidscan.key"), "node key, so a policy that revokes this boid keeps its own results")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: boidscan policy install FILE|-")
	}
	root, err := rf.maintainers()
	if err != nil {
		return err
	}
	b, err := readBundle(fs.Arg(0))
	if err != nil {
		return err
	}
	key, err := identity.Load(*keyFile)
	if err != nil {
		return fmt.Errorf("node key: %w", err)
	}
	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	state, changed, err := flockpolicy.Adopt(ctx, st, root, key.ID(), b, time.Now())
	if err != nil {
		return err
	}
	if !changed {
		return errors.New("nothing new in " + fs.Arg(0))
	}
	fmt.Printf("installed: policy %d", state.Serial())
	if state.Paused(time.Now()) {
		fmt.Printf(", emergency pause until %s", sig.Time(state.Pause.Expires))
	}
	fmt.Println()
	return nil
}

func cmdPolicyShow(ctx context.Context, args []string) error {
	var c common
	var ff flockFlags
	fs := flag.NewFlagSet("policy show", flag.ContinueOnError)
	c.register(fs, false)
	ff.register(fs)
	keyFile := fs.String("key-file", env("KEY_FILE", "boidscan.key"), "node key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cat, err := ff.catalog()
	if err != nil {
		return err
	}
	key, err := identity.Load(*keyFile)
	if err != nil {
		return fmt.Errorf("node key: %w", err)
	}
	st, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	state, err := st.PolicyState(ctx)
	if err != nil {
		return err
	}
	if p := state.Latest; p != nil {
		fmt.Printf("policy %d, issued %s, expires %s\n", p.Serial, sig.Time(p.Issued), sig.Time(p.Expires))
		fmt.Printf("pause %t, min_version %q, max_rate_pps %d, min_rescan %s, catalog %s\n",
			p.Pause, p.MinVersion, p.MaxRatePPS, time.Duration(p.MinRescan), sig.Short(p.Catalog))
		fmt.Printf("maintainers %s, %d revoked, seeds %s\n", shortIDs(p.Maintainers.Keys)+":"+strconv.Itoa(p.Maintainers.Threshold), len(p.RevokedNodes), strings.Join(p.Seeds, ", "))
	}
	if halt := state.Halt(time.Now(), policy.Version, cat.Hash(), key.ID()); halt != "" {
		fmt.Println("this boid does not sweep: " + halt)
	} else {
		fmt.Println("this boid may sweep")
	}
	return nil
}
