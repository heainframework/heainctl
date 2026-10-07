// Package ctl is heainctl: a thin client on heain-core's Config API
// (/v1/admin/*), with an admin certificate (Step 5a, author decisions
// 2026-10-08). It decides nothing itself: core checks every role, four-eyes
// and P5; heainctl sends what the identity asks for and shows the answer.
package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Version is set at build time (-ldflags "-X github.com/heainframework/heainctl/internal/ctl.Version=...").
var Version = "dev"

// boolFlags take no value.
var boolFlags = map[string]bool{"json": true, "dry-run": true, "replace": true, "follow": true, "subtree": true, "help": true, "h": true, "yes": true}

// valueFlags take one.
var valueFlags = map[string]bool{
	"config": true, "profile": true, "url": true, "cert": true, "key": true, "ca": true, "server-name": true, "node": true, "timeout": true,
	"data": true, "reason": true, "comment": true, "confirm-within": true, "from": true, "to": true, "limit": true, "since": true, "until": true,
	"types": true, "after": true, "wait": true, "out": true, "o": true, "bytes": true, "version": true, "kind": true, "app": true, "before": true,
	"targets": true, "canary": true, "soak": true,
}

// Opts are the parsed flags.
type Opts struct {
	v   map[string]string
	set map[string]bool
}

func (o Opts) S(k string) string { return o.v[k] }
func (o Opts) B(k string) bool   { return o.set[k] }
func (o Opts) Has(k string) bool { _, ok := o.v[k]; return ok || o.set[k] }

// parse splits flags (anywhere, -x or --x, --x=v) from positional words.
func parse(args []string) (Opts, []string, error) {
	o := Opts{v: map[string]string{}, set: map[string]bool{}}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		val, hasVal := "", false
		if k, v, ok := strings.Cut(name, "="); ok {
			name, val, hasVal = k, v, true
		}
		switch {
		case boolFlags[name]:
			if hasVal {
				b, err := strconv.ParseBool(val)
				if err != nil {
					return o, nil, fmt.Errorf("--%s takes true or false", name)
				}
				o.set[name] = b
			} else {
				o.set[name] = true
			}
		case valueFlags[name]:
			if !hasVal {
				if i+1 >= len(args) {
					return o, nil, fmt.Errorf("--%s needs a value", name)
				}
				i++
				val = args[i]
			}
			o.v[name] = val
		default:
			return o, nil, fmt.Errorf("unknown flag --%s", name)
		}
	}
	if o.v["o"] != "" && o.v["out"] == "" {
		o.v["out"] = o.v["o"]
	}
	return o, pos, nil
}

// Ctx is what a command runs with.
type Ctx struct {
	Opts   Opts
	Out    io.Writer
	Err    io.Writer
	Config *Config
	CfgAt  string
	ctx    context.Context
	client *Client
	prof   Profile
}

// Client connects lazily, so profile commands need no profile.
func (c *Ctx) Client() (*Client, error) {
	if c.client != nil {
		return c.client, nil
	}
	name := c.Opts.S("profile")
	if name == "" {
		name = os.Getenv("HEAINCTL_PROFILE")
	}
	if name == "" {
		name = c.Config.Current
	}
	p, ok := c.Config.Profiles[name]
	if name != "" && !ok {
		return nil, usage("no profile %q (heainctl profile list)", name)
	}
	for k, dst := range map[string]*string{"url": &p.URL, "cert": &p.Cert, "key": &p.Key, "ca": &p.CA, "server-name": &p.ServerName, "node": &p.Node} {
		if c.Opts.Has(k) {
			*dst = c.Opts.S(k)
		}
	}
	timeout := 60 * time.Second
	if t := c.Opts.S("timeout"); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return nil, usage("--timeout: %v", err)
		}
		timeout = d
	}
	cl, err := NewClient(p, timeout)
	if err != nil {
		return nil, usage("%v", err)
	}
	c.client, c.prof = cl, p
	return cl, nil
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usage(f string, a ...any) error { return &usageError{fmt.Sprintf(f, a...)} }

// call sends and prints: tables for lists (unless --json), pretty JSON
// otherwise.
func (c *Ctx) call(method, path string, body any, view *View) error {
	cl, err := c.Client()
	if err != nil {
		return err
	}
	out, ct, err := cl.Do(c.ctx, method, path, body)
	if err != nil {
		return err
	}
	return c.show(out, ct, view)
}

func (c *Ctx) show(out []byte, ct string, view *View) error {
	if !strings.Contains(ct, "json") && !json.Valid(out) {
		_, err := c.Out.Write(out)
		return err
	}
	if c.Opts.B("json") || view == nil {
		return pretty(c.Out, out)
	}
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		return pretty(c.Out, out)
	}
	if !view.render(c.Out, v) {
		return pretty(c.Out, out)
	}
	return nil
}

func pretty(w io.Writer, b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		_, err := w.Write(b)
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// value reads a command-line value: JSON when it parses, else a string.
func value(s string) json.RawMessage {
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	b, _ := json.Marshal(s)
	return b
}

// data is --data: inline JSON, @file, or @- (stdin).
func (c *Ctx) data(required bool) (map[string]any, error) {
	s := c.Opts.S("data")
	if s == "" {
		if required {
			return nil, usage("--data '<json>' or --data @file is needed")
		}
		return map[string]any{}, nil
	}
	var raw []byte
	var err error
	switch {
	case s == "@-":
		raw, err = io.ReadAll(os.Stdin)
	case strings.HasPrefix(s, "@"):
		raw, err = os.ReadFile(s[1:])
	default:
		raw = []byte(s)
	}
	if err != nil {
		return nil, usage("--data: %v", err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, usage("--data must be a JSON object: %v", err)
	}
	return m, nil
}

// fileJSON reads a JSON file (or - for stdin).
func fileJSON(path string) (json.RawMessage, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, usage("%v", err)
	}
	if !json.Valid(b) {
		return nil, usage("%s is not JSON", path)
	}
	return b, nil
}

// withOpt adds the common optional fields to a body.
func (c *Ctx) withOpt(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		switch k {
		case "dry-run", "replace":
			if c.Opts.B(k) {
				m[strings.ReplaceAll(k, "-", "_")] = true
			}
		default:
			if v := c.Opts.S(k); v != "" {
				m[strings.ReplaceAll(k, "-", "_")] = v
			}
		}
	}
	return m
}

func query(pairs ...string) string {
	q := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			q.Set(pairs[i], pairs[i+1])
		}
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

func esc(s string) string { return url.PathEscape(s) }

// Run runs heainctl with args (without the program name) and returns the
// exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, pos, err := parse(args)
	if err != nil {
		fmt.Fprintf(stderr, "heainctl: %v\n", err)
		return ExitUsage
	}
	if len(pos) == 0 || o.B("help") || o.B("h") || pos[0] == "help" {
		help(stdout, pos)
		if len(pos) == 0 && !o.B("help") && !o.B("h") {
			return ExitUsage
		}
		return ExitOK
	}
	if pos[0] == "version" {
		fmt.Fprintf(stdout, "heainctl %s\n", Version)
		return ExitOK
	}
	at := o.S("config")
	if at == "" {
		at = ConfigPath()
	}
	cfg, err := LoadConfig(at)
	if err != nil {
		fmt.Fprintf(stderr, "heainctl: %v\n", err)
		return ExitUsage
	}
	c := &Ctx{Opts: o, Out: stdout, Err: stderr, Config: cfg, CfgAt: at, ctx: ctx}
	cmd, rest := find(pos)
	if cmd == nil {
		fmt.Fprintf(stderr, "heainctl: unknown command %q (heainctl help)\n", strings.Join(pos, " "))
		return ExitUsage
	}
	if len(rest) < len(cmd.Args) || (!cmd.More && len(rest) > len(cmd.Args)+len(cmd.Opt)) {
		fmt.Fprintf(stderr, "usage: heainctl %s\n", cmd.usage())
		return ExitUsage
	}
	err = cmd.Run(c, rest)
	var ue *usageError
	var ae *APIError
	var ce *ConnError
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "heainctl: %v\n", err)
		return ExitUsage
	case errors.As(err, &ae):
		fmt.Fprintf(stderr, "heainctl: %v\n", err)
		return ExitAPI
	case errors.As(err, &ce):
		fmt.Fprintf(stderr, "heainctl: cannot reach core: %v\n", err)
		return ExitConnection
	default:
		fmt.Fprintf(stderr, "heainctl: %v\n", err)
		return ExitAPI
	}
}

// find matches the longest command words.
func find(pos []string) (*Command, []string) {
	var best *Command
	n := 0
	for i := range Commands {
		w := Commands[i].Words
		if len(w) <= len(pos) && len(w) > n && strings.Join(pos[:len(w)], " ") == strings.Join(w, " ") {
			best, n = &Commands[i], len(w)
		}
	}
	if best == nil {
		return nil, nil
	}
	return best, pos[n:]
}

func help(w io.Writer, pos []string) {
	topic := ""
	if len(pos) > 1 && pos[0] == "help" {
		topic = pos[1]
	}
	if topic == "" {
		fmt.Fprint(w, `heainctl -- heain-core's Config API (/v1/admin/*) with an admin certificate.

  heainctl [global flags] <area> <verb> [args] [flags]

Global flags:
  --profile NAME       a profile from the config file (default: the current one, or $HEAINCTL_PROFILE)
  --url, --cert, --key, --ca, --server-name    override the profile
  --node ID            run the command on node ID below the profile's node (remote admin through the Master)
  --json               print core's answer exactly (for scripts)
  --timeout 60s        --config PATH (default $HEAINCTL_CONFIG or ~/.config/heainctl/config.json)

Exit codes: 0 ok, 1 core refused (its code and message are printed), 2 usage, 3 core unreachable.

Areas: `)
		var areas []string
		seen := map[string]bool{}
		for _, c := range Commands {
			if !seen[c.Words[0]] {
				seen[c.Words[0]] = true
				areas = append(areas, c.Words[0])
			}
		}
		fmt.Fprintf(w, "%s\n\nheainctl help <area> lists its commands.\n", strings.Join(areas, ", "))
		return
	}
	var lines []string
	for _, c := range Commands {
		if c.Words[0] == topic {
			lines = append(lines, fmt.Sprintf("  heainctl %-58s %s", c.usage(), c.Help))
		}
	}
	sort.Strings(lines)
	if len(lines) == 0 {
		fmt.Fprintf(w, "no area %q\n", topic)
		return
	}
	fmt.Fprintln(w, strings.Join(lines, "\n"))
}
