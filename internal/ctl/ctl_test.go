package ctl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type pki struct {
	dir    string
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	serial int64
}

func newPKI(t *testing.T) *pki {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	ca, _ := x509.ParseCertificate(der)
	p := &pki{dir: t.TempDir(), ca: ca, caKey: k, serial: 1}
	p.write("ca.pem", "CERTIFICATE", der, 0o644)
	return p
}

func (p *pki) write(name, typ string, der []byte, perm os.FileMode) string {
	f := filepath.Join(p.dir, name)
	_ = os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), perm)
	return f
}

// issue makes a certificate for cn (with 127.0.0.1 for a server).
func (p *pki) issue(cn string, server bool) (string, string, tls.Certificate) {
	p.serial++
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	if server {
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tpl.DNSNames = []string{cn}
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, p.ca, &k.PublicKey, p.caKey)
	kd, _ := x509.MarshalECPrivateKey(k)
	cf := p.write(cn+".pem", "CERTIFICATE", der, 0o644)
	kf := p.write(cn+".key", "EC PRIVATE KEY", kd, 0o600)
	pair, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
	return cf, kf, pair
}

type seen struct {
	Method, Path, CN, Body, CT string
}

type fakeCore struct {
	mu   sync.Mutex
	reqs []seen
	srv  *httptest.Server
}

func (f *fakeCore) last() seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[len(f.reqs)-1]
}

func startCore(t *testing.T, p *pki) *fakeCore {
	_, _, pair := p.issue("G", true)
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	f := &fakeCore{}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, seen{r.Method, r.URL.RequestURI(), r.TLS.PeerCertificates[0].Subject.CommonName, string(b), r.Header.Get("Content-Type")})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/admin/whoami":
			_, _ = w.Write([]byte(`{"node":"G","identity":"` + r.TLS.PeerCertificates[0].Subject.CommonName + `","roles":["operator","viewer"],"approver":false}`))
		case r.URL.Path == "/v1/admin/policy/pending":
			_, _ = w.Write([]byte(`{"actions":[{"ID":"act-1","Type":"app.register","Category":"ALLOWLIST_BASED","ProposedBy":"admin","Status":"WAITING_APPROVAL"}]}`))
		case r.URL.Path == "/v1/admin/config":
			_, _ = w.Write([]byte(`{"node_id":"G","fields":[{"key":"heartbeat.interval","part":"system","value":"5s","origin":"local"},{"key":"p5.thresholds","part":"policy","value":{"x":1},"origin":"default"}]}`))
		case strings.HasSuffix(r.URL.Path, "/approve"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"self_approval","message":"the proposer cannot approve its own item"}}`))
		case r.URL.Path == "/v1/admin/legal-hold":
			http.Error(w, "this node has no P4 staging configured", http.StatusBadRequest)
		case r.URL.Path == "/v1/admin/diagnostics/bundle":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write([]byte{0x1f, 0x8b, 1, 2, 3})
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var o, e bytes.Buffer
	code := Run(context.Background(), args, &o, &e)
	return code, o.String(), e.String()
}

func TestParse(t *testing.T) {
	o, pos, err := parse([]string{"config", "--json", "set", "--profile=prod", "k", "-o", "f", "v", "--dry-run=false"})
	if err != nil || strings.Join(pos, " ") != "config set k v" || !o.B("json") || o.S("profile") != "prod" || o.S("out") != "f" || o.B("dry-run") {
		t.Fatalf("parse: %v %v %+v", err, pos, o)
	}
	for _, bad := range [][]string{{"--nope"}, {"--url"}, {"--json=maybe"}} {
		if _, _, err := parse(bad); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
	if string(value(`{"a":1}`)) != `{"a":1}` || string(value("5s")) != `"5s"` || string(value("12")) != "12" {
		t.Fatal("value")
	}
	c := &Client{Node: "w-1"}
	if c.Path("/v1/admin/config") != "/v1/admin/nodes/w-1/admin/config" || c.Path("/v1/admin/nodes/w-1") != "/v1/admin/nodes/w-1" || c.Path("/provision/token") != "/provision/token" {
		t.Fatal("remote paths")
	}
}

func TestAgainstCore(t *testing.T) {
	p := newPKI(t)
	core := startCore(t, p)
	cert, key, _ := p.issue("ops-admin", false)
	cfg := filepath.Join(t.TempDir(), "heainctl", "config.json")
	base := []string{"--config", cfg}
	a := func(x ...string) []string { return append(append([]string{}, base...), x...) }

	// no profile yet
	if code, _, e := run(t, a("whoami")...); code != ExitUsage || !strings.Contains(e, "profile add") {
		t.Fatalf("no profile: %d %s", code, e)
	}
	if code, out, e := run(t, a("profile", "add", "g", "--url", core.srv.URL, "--cert", cert, "--key", key, "--ca", filepath.Join(p.dir, "ca.pem"))...); code != 0 || !strings.Contains(out, "current: g") {
		t.Fatalf("profile add: %d %s %s", code, out, e)
	}
	if fi, _ := os.Stat(cfg); fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v", fi.Mode())
	}
	raw, _ := os.ReadFile(cfg)
	if bytes.Contains(raw, []byte("PRIVATE KEY")) || !bytes.Contains(raw, []byte(key)) {
		t.Fatal("the profile must name the key file, never hold the key")
	}
	// tables and JSON
	if code, out, _ := run(t, a("whoami")...); code != 0 || !strings.Contains(out, "identity:") || !strings.Contains(out, "ops-admin") || !strings.Contains(out, "operator,viewer") {
		t.Fatalf("whoami: %s", out)
	}
	if code, out, _ := run(t, a("policy", "pending")...); code != 0 || !strings.Contains(out, "ID") || !strings.Contains(out, "act-1") || !strings.Contains(out, "app.register") {
		t.Fatalf("pending table: %s", out)
	}
	if code, out, _ := run(t, a("policy", "pending", "--json")...); code != 0 || !json.Valid([]byte(out)) || !strings.Contains(out, `"actions"`) {
		t.Fatalf("pending json: %s", out)
	}
	if code, out, _ := run(t, a("config", "get", "p5.thresholds")...); code != 0 || !strings.Contains(out, "policy") {
		t.Fatalf("config get: %s", out)
	}
	if code, _, e := run(t, a("config", "get", "nope")...); code != ExitUsage || !strings.Contains(e, "no key nope") {
		t.Fatalf("config get unknown: %s", e)
	}
	// bodies
	run(t, a("config", "set", "heartbeat.interval", "7s")...)
	if l := core.last(); l.Method != "PUT" || l.Path != "/v1/admin/config/system/heartbeat.interval" || l.Body != `{"value":"7s"}` || l.CN != "ops-admin" {
		t.Fatalf("config set: %+v", l)
	}
	run(t, a("config", "propose", "p5.thresholds", `{"a":2}`, "--reason", "busier")...)
	if l := core.last(); l.Method != "POST" || l.Body != `{"reason":"busier","value":{"a":2}}` {
		t.Fatalf("config propose: %+v", l)
	}
	run(t, a("legal-hold", "set", "t-1", "t-2", "--reason", "court order")...)
	if l := core.last(); l.Body != `{"reason":"court order","ticket_ids":["t-1","t-2"]}` {
		t.Fatalf("hold: %+v", l)
	}
	if code, _, e := run(t, a("legal-hold", "set", "t-1")...); code != ExitUsage || !strings.Contains(e, "--reason") {
		t.Fatal("hold without reason")
	}
	run(t, a("rollouts", "create", "--version", "1.3.2", "--targets", "w-1,w-2", "--canary", "1", "--dry-run")...)
	if l := core.last(); l.Body != `{"canary":1,"dry_run":true,"targets":["w-1","w-2"],"version":"1.3.2"}` {
		t.Fatalf("rollout: %+v", l)
	}
	// remote admin through the Master
	run(t, a("config", "list", "--node", "w-1")...)
	if l := core.last(); l.Path != "/v1/admin/nodes/w-1/admin/config" {
		t.Fatalf("remote: %+v", l)
	}
	// a binary upload
	bin := filepath.Join(t.TempDir(), "node")
	_ = os.WriteFile(bin, []byte("BINARY"), 0o755)
	run(t, a("releases", "upload", "1.3.2", bin)...)
	if l := core.last(); l.Method != "PUT" || l.Path != "/v1/admin/releases/1.3.2/binary" || l.Body != "BINARY" || l.CT != "application/octet-stream" {
		t.Fatalf("upload: %+v", l)
	}
	// files out
	tok := filepath.Join(t.TempDir(), "tok.json")
	if code, _, _ := run(t, a("provision", "token", "shop.s1", "-o", tok, "--node", "w-1")...); code != 0 {
		t.Fatal("token")
	}
	if l := core.last(); l.Path != "/provision/token" || l.Body != `{"label":"shop.s1"}` {
		t.Fatalf("token: %+v", l)
	}
	if fi, _ := os.Stat(tok); fi.Mode().Perm() != 0o600 {
		t.Fatal("a token file must be 0600")
	}
	bf := filepath.Join(t.TempDir(), "b.tgz")
	if code, _, _ := run(t, a("diagnostics", "bundle", "-o", bf)...); code != 0 {
		t.Fatal("bundle")
	}
	if b, _ := os.ReadFile(bf); !bytes.Equal(b, []byte{0x1f, 0x8b, 1, 2, 3}) {
		t.Fatal("bundle bytes")
	}
	// errors: core's code and message, exit 1; plain-text errors too
	if code, _, e := run(t, a("policy", "approve", "act-1")...); code != ExitAPI || !strings.Contains(e, "403 self_approval: the proposer cannot approve") {
		t.Fatalf("approve: %d %s", code, e)
	}
	if code, _, e := run(t, a("legal-hold", "list")...); code != ExitAPI || !strings.Contains(e, "400: this node has no P4 staging") {
		t.Fatalf("plain error: %d %s", code, e)
	}
	// usage
	if code, _, _ := run(t, a("config", "set", "k")...); code != ExitUsage {
		t.Fatal("missing argument")
	}
	if code, _, _ := run(t, a("frobnicate")...); code != ExitUsage {
		t.Fatal("unknown command")
	}
	// a server whose certificate is not from the deployment's CA: refused (exit 3), nothing sent
	other := newPKI(t)
	bad := startCore(t, other)
	n := len(core.reqs)
	if code, _, e := run(t, a("whoami", "--url", bad.srv.URL)...); code != ExitConnection || !strings.Contains(e, "certificate") {
		t.Fatalf("foreign server: %d %s", code, e)
	}
	if len(bad.reqs) != 0 || len(core.reqs) != n {
		t.Fatal("a request reached a server that did not verify")
	}
	// nothing listening
	if code, _, _ := run(t, a("whoami", "--url", "https://127.0.0.1:1")...); code != ExitConnection {
		t.Fatal("unreachable")
	}
	// profiles
	run(t, a("profile", "add", "w", "--url", core.srv.URL, "--cert", cert, "--key", key, "--ca", filepath.Join(p.dir, "ca.pem"), "--node", "w-1")...)
	if code, out, _ := run(t, a("profile", "list")...); code != 0 || !strings.Contains(out, "*        g") || !strings.Contains(out, "w-1") {
		t.Fatalf("list: %s", out)
	}
	run(t, a("--profile", "w", "inventory")...)
	if l := core.last(); l.Path != "/v1/admin/nodes/w-1/admin/inventory" {
		t.Fatalf("profile node: %+v", l)
	}
	if code, _, _ := run(t, a("profile", "use", "nope")...); code != ExitUsage {
		t.Fatal("use unknown")
	}
	run(t, a("profile", "remove", "g")...)
	if c, _ := LoadConfig(cfg); c.Current != "" || len(c.Profiles) != 1 {
		t.Fatalf("remove: %+v", c)
	}
}

func TestViews(t *testing.T) {
	var b bytes.Buffer
	v := &View{Array: "events", Cols: []string{"seq", "type", "data.x"}}
	if !v.render(&b, map[string]any{"events": []any{map[string]any{"seq": 3.0, "type": "alert.raised", "data": map[string]any{"x": true}}}}) ||
		!strings.Contains(b.String(), "SEQ") || !strings.Contains(b.String(), "DATA_X") || !strings.Contains(b.String(), "alert.raised") || !strings.Contains(b.String(), "yes") {
		t.Fatalf("table: %s", b.String())
	}
	b.Reset()
	if !v.render(&b, map[string]any{"events": nil}) || !strings.Contains(b.String(), "(none)") {
		t.Fatalf("empty: %s", b.String())
	}
	b.Reset()
	// columns that do not exist fall back to the item's scalar fields
	if !(&View{Cols: []string{"zzz"}}).render(&b, []any{map[string]any{"id": "n1", "tier": "ZONE", "sub": map[string]any{}}}) || !strings.Contains(b.String(), "TIER") || strings.Contains(b.String(), "SUB") {
		t.Fatalf("fallback: %s", b.String())
	}
	if (&View{Array: "x"}).render(&b, map[string]any{"x": "not a list"}) {
		t.Fatal("a non-list must fall back to JSON")
	}
}
