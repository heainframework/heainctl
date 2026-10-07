package ctl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// Command is one heainctl command.
type Command struct {
	Words []string
	Args  []string // required positional arguments
	Opt   []string // optional ones
	More  bool     // any number more
	Help  string
	Run   func(c *Ctx, a []string) error
}

func (c Command) usage() string {
	s := strings.Join(c.Words, " ")
	for _, a := range c.Args {
		s += " " + a
	}
	for _, a := range c.Opt {
		s += " [" + a + "]"
	}
	if c.More {
		s += " ..."
	}
	return s
}

// get / post / ... are commands that only call core.
func get(path string, v *View) func(*Ctx, []string) error {
	return func(c *Ctx, _ []string) error { return c.call(http.MethodGet, path, nil, v) }
}

func post(path string) func(*Ctx, []string) error {
	return func(c *Ctx, _ []string) error { return c.call(http.MethodPost, path, map[string]any{}, nil) }
}

var (
	kv        = &View{KV: true}
	pendingV  = &View{Array: "actions", Cols: []string{"ID", "Type", "Category", "ProposedBy", "Status", "Value", "Node"}}
	nodesV    = &View{Array: "nodes", Cols: []string{"node", "depth", "parent", "core_version", "config_version", "leader", "p5_waiting", "age_seconds"}}
	configV   = &View{Array: "fields", Cols: []string{"key", "part", "value", "origin", "locked", "updated_by"}}
	appsV     = &View{Array: "apps", Cols: []string{"app_id", "version", "status", "instances", "admitted"}}
	eventsV   = &View{Array: "events", Cols: []string{"seq", "at", "node", "type", "actor", "result", "severity"}}
	auditV    = &View{Array: "records", Cols: []string{"seq", "event.Timestamp", "event.Actor", "event.Action", "event.Result"}}
	alertsV   = &View{Array: "alerts", Cols: []string{"id", "rule", "node", "severity", "since", "message"}}
	rolloutsV = &View{Cols: []string{"id", "kind", "app", "version", "state", "phase", "current", "created"}}
	historyV  = &View{Cols: []string{"version", "n", "at", "by", "comment", "status", "confirmed"}}
	journalV  = &View{Array: "entries", Cols: []string{"seq", "hlc", "kind", "type", "at"}}
)

// Commands is every heainctl command.
var Commands = []Command{
	// ---- profiles (local) ----
	{Words: []string{"profile", "add"}, Args: []string{"NAME"}, Help: "save a profile: --url https://host:port --cert admin.pem --key admin.key --ca ca.pem [--server-name] [--node]", Run: profileAdd},
	{Words: []string{"profile", "use"}, Args: []string{"NAME"}, Help: "make it the current profile", Run: profileUse},
	{Words: []string{"profile", "list"}, Help: "the saved profiles", Run: profileList},
	{Words: []string{"profile", "show"}, Opt: []string{"NAME"}, Help: "one profile (default: the current one)", Run: profileShow},
	{Words: []string{"profile", "remove"}, Args: []string{"NAME"}, Help: "forget a profile (its files stay)", Run: profileRemove},

	// ---- who and where ----
	{Words: []string{"whoami"}, Help: "the identity core sees, its roles here, whether it is an Approver", Run: get("/v1/admin/whoami", kv)},
	{Words: []string{"nodes", "list"}, Help: "this node and every node below it (the fleet view)", Run: get("/v1/admin/nodes", nodesV)},
	{Words: []string{"nodes", "get"}, Args: []string{"ID"}, Help: "one node of the subtree", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodGet, "/v1/admin/nodes/"+esc(a[0]), nil, nil)
	}},
	{Words: []string{"roles", "list"}, Help: "role assignments and slot owners at this scope", Run: get("/v1/admin/roles", nil)},
	{Words: []string{"roles", "set"}, Args: []string{"NODE"}, Help: "assign a node's role: --data '{...}' (a raise outside policy waits for P5)", Run: func(c *Ctx, a []string) error {
		d, err := c.data(true)
		if err != nil {
			return err
		}
		return c.call(http.MethodPut, "/v1/admin/roles/"+esc(a[0]), d, nil)
	}},

	// ---- config ----
	{Words: []string{"config", "list"}, Help: "every key: part (system 2a / policy 2b), value, origin, lock", Run: get("/v1/admin/config", configV)},
	{Words: []string{"config", "get"}, Args: []string{"KEY"}, Help: "one key", Run: configGet},
	{Words: []string{"config", "set"}, Args: []string{"KEY", "VALUE"}, Help: "a system key (2a): applied at once, audited; VALUE is JSON or a string", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPut, "/v1/admin/config/system/"+esc(a[0]), map[string]any{"value": value(a[1])}, kv)
	}},
	{Words: []string{"config", "propose"}, Args: []string{"KEY", "VALUE"}, Help: "a policy key (2b): proposed to P5 [--reason]", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/config/policy/"+esc(a[0]), c.withOpt(map[string]any{"value": value(a[1])}, "reason"), kv)
	}},
	{Words: []string{"config", "changes"}, Help: "several keys at once: --data '{\"set\":{...},\"unset\":[...]}' [--dry-run] [--confirm-within 10m] [--comment]", Run: func(c *Ctx, _ []string) error {
		d, err := c.data(true)
		if err != nil {
			return err
		}
		return c.call(http.MethodPost, "/v1/admin/config/changes", c.withOpt(d, "dry-run", "confirm-within", "comment"), nil)
	}},
	{Words: []string{"config", "history"}, Help: "applied versions [--before N] [--limit N]", Run: func(c *Ctx, _ []string) error {
		return c.call(http.MethodGet, "/v1/admin/config/history"+query("before", c.Opts.S("before"), "limit", c.Opts.S("limit")), nil, historyV)
	}},
	{Words: []string{"config", "version"}, Args: []string{"N"}, Help: "one version of the history", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodGet, "/v1/admin/config/history/"+esc(a[0]), nil, nil)
	}},
	{Words: []string{"config", "confirm"}, Args: []string{"N"}, Help: "keep a change made with --confirm-within (otherwise core reverts it)", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/config/history/"+esc(a[0])+"/confirm", map[string]any{}, nil)
	}},
	{Words: []string{"config", "diff"}, Args: []string{"FROM"}, Opt: []string{"TO"}, Help: "what changed between two versions", Run: func(c *Ctx, a []string) error {
		to := ""
		if len(a) > 1 {
			to = a[1]
		}
		return c.call(http.MethodGet, "/v1/admin/config/diff"+query("from", a[0], "to", to), nil, nil)
	}},
	{Words: []string{"config", "export"}, Help: "the whole config as JSON [-o FILE]", Run: func(c *Ctx, _ []string) error {
		return c.save(http.MethodGet, "/v1/admin/config/export", nil, 0o644)
	}},
	{Words: []string{"config", "import"}, Args: []string{"FILE"}, Help: "apply an export [--replace] [--dry-run] [--confirm-within] [--comment]", Run: func(c *Ctx, a []string) error {
		f, err := fileJSON(a[0])
		if err != nil {
			return err
		}
		return c.call(http.MethodPost, "/v1/admin/config/import", c.withOpt(map[string]any{"config": f}, "replace", "dry-run", "confirm-within", "comment"), nil)
	}},
	{Words: []string{"config", "rollback"}, Args: []string{"VERSION"}, Help: "back to a version [--dry-run] [--confirm-within] [--comment]", Run: func(c *Ctx, a []string) error {
		n, err := strconv.Atoi(a[0])
		if err != nil {
			return usage("VERSION is a number")
		}
		return c.call(http.MethodPost, "/v1/admin/config/rollback", c.withOpt(map[string]any{"version": n}, "dry-run", "confirm-within", "comment"), nil)
	}},
	{Words: []string{"config", "drift"}, Opt: []string{"BASELINE"}, Help: "keys that differ from the parent's (or from a baseline export)", Run: func(c *Ctx, a []string) error {
		if len(a) == 0 {
			return c.call(http.MethodGet, "/v1/admin/config/drift", nil, nil)
		}
		f, err := fileJSON(a[0])
		if err != nil {
			return err
		}
		return c.call(http.MethodPost, "/v1/admin/config/drift", map[string]any{"baseline": f}, nil)
	}},

	// ---- P5 ----
	{Words: []string{"policy", "pending"}, Help: "items waiting for an Approver here [--subtree: and below]", Run: func(c *Ctx, _ []string) error {
		if c.Opts.B("subtree") {
			return c.call(http.MethodGet, "/v1/admin/policy/subtree", nil, &View{Cols: pendingV.Cols})
		}
		return c.call(http.MethodGet, "/v1/admin/policy/pending", nil, pendingV)
	}},
	{Words: []string{"policy", "approve"}, Args: []string{"ACTION_ID"}, Help: "approve (an Approver, never the proposer) [--reason]", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/policy/"+esc(a[0])+"/approve", c.withOpt(map[string]any{}, "reason"), kv)
	}},
	{Words: []string{"policy", "reject"}, Args: []string{"ACTION_ID"}, Help: "reject (an Approver, never the proposer) [--reason]", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/policy/"+esc(a[0])+"/reject", c.withOpt(map[string]any{}, "reason"), kv)
	}},

	// ---- apps ----
	{Words: []string{"apps", "list"}, Help: "admitted apps and their instances", Run: get("/v1/admin/apps", appsV)},
	{Words: []string{"apps", "instances"}, Help: "what runs on this node", Run: get("/v1/admin/apps/instances", &View{})},
	{Words: []string{"apps", "packages"}, Help: "signed packages on this node", Run: get("/v1/admin/apps/packages", &View{})},
	{Words: []string{"apps", "deploy"}, Args: []string{"APP", "VERSION"}, Help: "run that version here (P5 app.deploy) [--reason]", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/apps/deploy", c.withOpt(map[string]any{"app": a[0], "version": a[1]}, "reason"), kv)
	}},
	{Words: []string{"apps", "stop"}, Args: []string{"INSTANCE"}, Help: "stop an instance", Run: instance("stop")},
	{Words: []string{"apps", "start"}, Args: []string{"INSTANCE"}, Help: "start an instance", Run: instance("start")},
	{Words: []string{"apps", "restart"}, Args: []string{"INSTANCE"}, Help: "restart an instance", Run: instance("restart")},
	{Words: []string{"apps", "remove"}, Args: []string{"APP"}, Help: "stop and remove the app here", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/apps/remove", map[string]any{"app": a[0]}, nil)
	}},
	{Words: []string{"apps", "rollback"}, Args: []string{"APP"}, Help: "back to the version before", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/apps/rollback", map[string]any{"app": a[0]}, nil)
	}},
	{Words: []string{"apps", "package-add"}, Args: []string{"PACKAGE_JSON"}, Help: "add a signed package (heain-release app-package; security-admin)", Run: func(c *Ctx, a []string) error {
		f, err := fileJSON(a[0])
		if err != nil {
			return err
		}
		return c.call(http.MethodPost, "/v1/admin/apps/packages", map[string]any{"package": f}, nil)
	}},
	{Words: []string{"apps", "package-upload"}, Args: []string{"APP", "VERSION", "ARCHIVE"}, Help: "its archive (checked against the package)", Run: func(c *Ctx, a []string) error {
		return c.upload("/v1/admin/apps/packages/"+esc(a[0])+"/"+esc(a[1])+"/archive", a[2])
	}},
	{Words: []string{"apps", "package-fetch"}, Args: []string{"APP", "VERSION"}, Help: "fetch it from the parent, hop by hop", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/apps/packages/"+esc(a[0])+"/"+esc(a[1])+"/fetch", map[string]any{}, nil)
	}},

	// ---- releases, upgrades, rollouts ----
	{Words: []string{"releases", "list"}, Help: "releases here, the slots, a trial in progress", Run: get("/v1/admin/releases", nil)},
	{Words: []string{"releases", "add"}, Args: []string{"RELEASE_JSON"}, Help: "add a signed release (heain-release; security-admin)", Run: func(c *Ctx, a []string) error {
		f, err := fileJSON(a[0])
		if err != nil {
			return err
		}
		return c.call(http.MethodPost, "/v1/admin/releases", map[string]any{"release": f}, nil)
	}},
	{Words: []string{"releases", "upload"}, Args: []string{"VERSION", "BINARY"}, Help: "its binary (checked against the release)", Run: func(c *Ctx, a []string) error {
		return c.upload("/v1/admin/releases/"+esc(a[0])+"/binary", a[1])
	}},
	{Words: []string{"releases", "fetch"}, Args: []string{"VERSION"}, Help: "fetch it from the parent, hop by hop", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/releases/"+esc(a[0])+"/fetch", map[string]any{}, nil)
	}},
	{Words: []string{"upgrade", "apply"}, Args: []string{"VERSION"}, Help: "upgrade this node (P5 upgrade.apply) [--reason]", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/upgrade", c.withOpt(map[string]any{"version": a[0]}, "reason"), kv)
	}},
	{Words: []string{"upgrade", "rollback"}, Help: "back to the previous slot now [--reason]", Run: func(c *Ctx, _ []string) error {
		return c.call(http.MethodPost, "/v1/admin/upgrade/rollback", c.withOpt(map[string]any{}, "reason"), kv)
	}},
	{Words: []string{"rollouts", "list"}, Help: "rollouts and where they stand", Run: get("/v1/admin/rollouts", rolloutsV)},
	{Words: []string{"rollouts", "get"}, Args: []string{"ID"}, Help: "one rollout", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodGet, "/v1/admin/rollouts/"+esc(a[0]), nil, nil)
	}},
	{Words: []string{"rollouts", "create"}, Help: "plan one: --version V [--kind core|app --app A] [--targets a,b] [--canary N] [--soak 10m] [--comment] [--dry-run] or --data", Run: rolloutCreate},
	{Words: []string{"rollouts", "pause"}, Args: []string{"ID"}, Help: "pause", Run: rollout("pause")},
	{Words: []string{"rollouts", "resume"}, Args: []string{"ID"}, Help: "resume", Run: rollout("resume")},
	{Words: []string{"rollouts", "abort"}, Args: []string{"ID"}, Help: "abort", Run: rollout("abort")},
	{Words: []string{"rollouts", "rollback"}, Args: []string{"ID"}, Help: "roll back what it did", Run: rollout("rollback")},

	// ---- audit and observation ----
	{Words: []string{"audit", "list"}, Help: "the audit chain [--from SEQ] [--limit N]", Run: func(c *Ctx, _ []string) error {
		return c.call(http.MethodGet, "/v1/admin/audit"+query("from", c.Opts.S("from"), "limit", c.Opts.S("limit")), nil, auditV)
	}},
	{Words: []string{"audit", "verify"}, Help: "recompute every link of the chain", Run: get("/v1/admin/audit/verify", kv)},
	{Words: []string{"journal", "list"}, Help: "the standalone journal [--from SEQ] [--limit N]", Run: func(c *Ctx, _ []string) error {
		return c.call(http.MethodGet, "/v1/admin/journal"+query("from", c.Opts.S("from"), "limit", c.Opts.S("limit")), nil, journalV)
	}},
	{Words: []string{"journal", "verify"}, Help: "verify the journal's chain", Run: get("/v1/admin/journal/verify", kv)},
	{Words: []string{"metrics", "list"}, Help: "samples [--since 1h|RFC3339] [--until] [--limit]", Run: func(c *Ctx, _ []string) error {
		return c.call(http.MethodGet, "/v1/admin/metrics"+query("since", c.Opts.S("since"), "until", c.Opts.S("until"), "limit", c.Opts.S("limit")), nil, nil)
	}},
	{Words: []string{"metrics", "latest"}, Help: "the latest sample", Run: get("/v1/admin/metrics/latest", nil)},
	{Words: []string{"inventory"}, Help: "hardware and software of this node", Run: get("/v1/admin/inventory", nil)},
	{Words: []string{"alerts"}, Help: "active alerts", Run: get("/v1/admin/alerts", alertsV)},
	{Words: []string{"events"}, Help: "events [--after SEQ] [--types alert.*,config.*] [--wait 20s] [--follow]", Run: events},

	// ---- governance, holds, break-glass ----
	{Words: []string{"legal-hold", "list"}, Help: "staged artifacts under legal hold", Run: get("/v1/admin/legal-hold", nil)},
	{Words: []string{"legal-hold", "set"}, Args: []string{"TICKET"}, More: true, Help: "hold (2a, at once) --reason", Run: hold("/v1/admin/legal-hold")},
	{Words: []string{"legal-hold", "lift"}, Args: []string{"TICKET"}, More: true, Help: "lift (2b, P5) --reason", Run: hold("/v1/admin/legal-hold/lift")},
	{Words: []string{"duty-profiles", "list"}, Help: "duty profiles", Run: get("/v1/admin/duty-profiles", nil)},
	{Words: []string{"duty-profiles", "set"}, Args: []string{"SLOT", "FILE"}, Help: "propose a slot's profile (P5)", Run: func(c *Ctx, a []string) error {
		f, err := fileJSON(a[1])
		if err != nil {
			return err
		}
		return c.call(http.MethodPut, "/v1/admin/duty-profiles/"+esc(a[0]), f, kv)
	}},
	{Words: []string{"governance", "metrics"}, Help: "Escalation Saturation: drift per policy key", Run: get("/v1/admin/governance/metrics", nil)},
	{Words: []string{"governance", "ack"}, Args: []string{"POLICY_KEY"}, Help: "acknowledge a review (an Approver)", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/governance/"+esc(a[0])+"/acknowledge", c.withOpt(map[string]any{}, "comment"), nil)
	}},
	{Words: []string{"breakglass", "status"}, Help: "whether break-glass is in use", Run: get("/v1/admin/breakglass", kv)},
	{Words: []string{"breakglass", "ack"}, Help: "an Approver acknowledges its use --comment", Run: func(c *Ctx, _ []string) error {
		return c.call(http.MethodPost, "/v1/admin/breakglass/ack", c.withOpt(map[string]any{}, "comment"), nil)
	}},

	// ---- diagnostics and provisioning ----
	{Words: []string{"diagnostics", "bundle"}, Help: "a support bundle (tar.gz) of this node -o FILE", Run: func(c *Ctx, _ []string) error {
		if c.Opts.S("out") == "" {
			return usage("-o FILE is needed (the bundle is a tar.gz)")
		}
		return c.save(http.MethodGet, "/v1/admin/diagnostics/bundle", nil, 0o600)
	}},
	{Words: []string{"diagnostics", "logs"}, Args: []string{"APP.INSTANCE"}, Help: "the tail of an app instance's log [--bytes N]", Run: func(c *Ctx, a []string) error {
		return c.call(http.MethodGet, "/v1/admin/diagnostics/logs/"+esc(a[0])+query("bytes", c.Opts.S("bytes")), nil, nil)
	}},
	{Words: []string{"diagnostics", "matrix"}, Help: "every node of the subtree runs the checks", Run: get("/v1/admin/diagnostics/matrix", nil)},
	{Words: []string{"diagnostics", "connectivity"}, Help: "this node to its parent, peers and apps", Run: get("/v1/admin/diagnostics/connectivity", nil)},
	{Words: []string{"provision", "token"}, Args: []string{"LABEL"}, Help: "a one-time provisioning token (for an app: <app>.<instance>) -o FILE (0600)", Run: func(c *Ctx, a []string) error {
		return c.save(http.MethodPost, "/provision/token", map[string]any{"label": a[0]}, 0o600)
	}},

	// ---- anything else ----
	{Words: []string{"raw"}, Args: []string{"METHOD", "PATH"}, Help: "any request: heainctl raw GET /v1/admin/... [--data JSON|@file] (--node applies to /v1/admin paths)", Run: func(c *Ctx, a []string) error {
		m := strings.ToUpper(a[0])
		if !strings.HasPrefix(a[1], "/") {
			return usage("PATH starts with /")
		}
		var body any
		if c.Opts.S("data") != "" {
			d, err := c.data(true)
			if err != nil {
				return err
			}
			body = d
		}
		return c.call(m, a[1], body, nil)
	}},
}

func instance(verb string) func(*Ctx, []string) error {
	return func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/apps/instances/"+esc(a[0])+"/"+verb, map[string]any{}, nil)
	}
}

func rollout(verb string) func(*Ctx, []string) error {
	return func(c *Ctx, a []string) error {
		return c.call(http.MethodPost, "/v1/admin/rollouts/"+esc(a[0])+"/"+verb, c.withOpt(map[string]any{}, "comment"), nil)
	}
}

func hold(path string) func(*Ctx, []string) error {
	return func(c *Ctx, a []string) error {
		if c.Opts.S("reason") == "" {
			return usage("--reason is needed")
		}
		return c.call(http.MethodPost, path, map[string]any{"ticket_ids": a, "reason": c.Opts.S("reason")}, nil)
	}
}

func rolloutCreate(c *Ctx, _ []string) error {
	d, err := c.data(false)
	if err != nil {
		return err
	}
	for _, k := range []string{"kind", "app", "version", "soak", "comment"} {
		if v := c.Opts.S(k); v != "" {
			d[k] = v
		}
	}
	if t := c.Opts.S("targets"); t != "" {
		d["targets"] = strings.Split(t, ",")
	}
	if n := c.Opts.S("canary"); n != "" {
		d["canary"] = value(n)
	}
	if c.Opts.B("dry-run") {
		d["dry_run"] = true
	}
	if d["version"] == nil {
		return usage("--version is needed")
	}
	return c.call(http.MethodPost, "/v1/admin/rollouts", d, nil)
}

func configGet(c *Ctx, a []string) error {
	cl, err := c.Client()
	if err != nil {
		return err
	}
	out, _, err := cl.Do(c.ctx, http.MethodGet, "/v1/admin/config", nil)
	if err != nil {
		return err
	}
	var snap struct {
		Fields []map[string]any `json:"fields"`
	}
	if err := json.Unmarshal(out, &snap); err != nil {
		return err
	}
	for _, f := range snap.Fields {
		if f["key"] == a[0] {
			b, _ := json.Marshal(f)
			if c.Opts.B("json") {
				return pretty(c.Out, b)
			}
			return c.show(b, "application/json", kv)
		}
	}
	return usage("no key %s on this node (heainctl config list)", a[0])
}

// save writes an answer to -o FILE (mode perm), or to stdout.
func (c *Ctx) save(method, path string, body any, perm os.FileMode) error {
	cl, err := c.Client()
	if err != nil {
		return err
	}
	if path == "/provision/token" {
		cl = &Client{Base: cl.Base, HTTP: cl.HTTP, Timeout: cl.Timeout} // not an admin path: never forwarded
	}
	out, _, err := cl.Do(c.ctx, method, path, body)
	if err != nil {
		return err
	}
	f := c.Opts.S("out")
	if f == "" {
		return pretty(c.Out, out)
	}
	if err := os.WriteFile(f, out, perm); err != nil {
		return err
	}
	fmt.Fprintf(c.Err, "heainctl: wrote %s (%d bytes)\n", f, len(out))
	return nil
}

func (c *Ctx) upload(path, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return usage("%v", err)
	}
	defer f.Close()
	cl, err := c.Client()
	if err != nil {
		return err
	}
	out, ct, err := cl.DoRaw(c.ctx, http.MethodPut, cl.Path(path), f, 30*time.Minute)
	if err != nil {
		return err
	}
	return c.show(out, ct, nil)
}

func events(c *Ctx, _ []string) error {
	cl, err := c.Client()
	if err != nil {
		return err
	}
	after := c.Opts.S("after")
	wait := c.Opts.S("wait")
	if c.Opts.B("follow") && wait == "" {
		wait = "20s"
	}
	for {
		out, ct, err := cl.DoRaw(c.ctx, http.MethodGet, cl.Path("/v1/admin/events"+query("after", after, "wait", wait, "types", c.Opts.S("types"))), nil, cl.Timeout+30*time.Second)
		if err != nil {
			return err
		}
		if !c.Opts.B("follow") {
			return c.show(out, ct, eventsV)
		}
		var page struct {
			Events []json.RawMessage `json:"events"`
			Last   uint64            `json:"last"`
		}
		if err := json.Unmarshal(out, &page); err != nil {
			return err
		}
		for _, e := range page.Events {
			if c.Opts.B("json") {
				fmt.Fprintln(c.Out, string(e))
				continue
			}
			var ev map[string]any
			_ = json.Unmarshal(e, &ev)
			fmt.Fprintf(c.Out, "%s  %s  %-10s %-32s %s %s\n", cell(ev["seq"]), cell(ev["at"]), cell(ev["node"]), cell(ev["type"]), cell(ev["actor"]), cell(ev["result"]))
		}
		if page.Last > 0 {
			after = strconv.FormatUint(page.Last, 10)
		}
		select {
		case <-c.ctx.Done():
			return nil
		default:
		}
	}
}

// ---- profiles ----

func profileAdd(c *Ctx, a []string) error {
	p := Profile{URL: c.Opts.S("url"), Cert: abs(c.Opts.S("cert")), Key: abs(c.Opts.S("key")), CA: abs(c.Opts.S("ca")),
		ServerName: c.Opts.S("server-name"), Node: c.Opts.S("node")}
	if p.URL == "" || p.Cert == "" || p.Key == "" || p.CA == "" {
		return usage("profile add NAME --url https://host:port --cert admin.pem --key admin.key --ca ca.pem")
	}
	for _, f := range []string{p.Cert, p.Key, p.CA} {
		if _, err := os.Stat(f); err != nil {
			return usage("%v", err)
		}
	}
	if _, err := NewClient(p, 0); err != nil {
		return usage("%v", err)
	}
	c.Config.Profiles[a[0]] = p
	if c.Config.Current == "" {
		c.Config.Current = a[0]
	}
	if err := c.Config.Save(c.CfgAt); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "profile %s saved in %s (current: %s)\n", a[0], c.CfgAt, c.Config.Current)
	return nil
}

func profileUse(c *Ctx, a []string) error {
	if _, ok := c.Config.Profiles[a[0]]; !ok {
		return usage("no profile %q", a[0])
	}
	c.Config.Current = a[0]
	if err := c.Config.Save(c.CfgAt); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "current profile: %s\n", a[0])
	return nil
}

func profileList(c *Ctx, _ []string) error {
	if c.Opts.B("json") {
		b, _ := json.Marshal(c.Config)
		return pretty(c.Out, b)
	}
	tw := tabwriter.NewWriter(c.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CURRENT\tNAME\tURL\tCERT\tNODE")
	for _, n := range c.Config.Names() {
		p := c.Config.Profiles[n]
		cur := ""
		if n == c.Config.Current {
			cur = "*"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", cur, n, p.URL, p.Cert, cell(p.Node))
	}
	return tw.Flush()
}

func profileShow(c *Ctx, a []string) error {
	n := c.Config.Current
	if len(a) > 0 {
		n = a[0]
	}
	p, ok := c.Config.Profiles[n]
	if !ok {
		return usage("no profile %q", n)
	}
	b, _ := json.Marshal(map[string]any{"name": n, "profile": p})
	return pretty(c.Out, b)
}

func profileRemove(c *Ctx, a []string) error {
	if _, ok := c.Config.Profiles[a[0]]; !ok {
		return usage("no profile %q", a[0])
	}
	delete(c.Config.Profiles, a[0])
	if c.Config.Current == a[0] {
		c.Config.Current = ""
	}
	if err := c.Config.Save(c.CfgAt); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "profile %s removed\n", a[0])
	return nil
}
