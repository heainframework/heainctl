package ctl

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Exit codes.
const (
	ExitOK         = 0
	ExitAPI        = 1 // core answered with an error
	ExitUsage      = 2
	ExitConnection = 3
)

// APIError is a non-2xx answer from core.
type APIError struct {
	Status  int
	Code    string
	Message string
	Body    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("%d: %s", e.Status, strings.TrimSpace(e.Message))
}

// ConnError: core could not be reached (or its certificate did not verify).
type ConnError struct{ Err error }

func (e *ConnError) Error() string { return e.Err.Error() }
func (e *ConnError) Unwrap() error { return e.Err }

// Client talks to one node's admin API with an admin certificate.
type Client struct {
	Base    string // https://host:port
	Node    string // remote admin: run /v1/admin/* on this node below (through the Master)
	HTTP    *http.Client
	Timeout time.Duration
}

// NewClient builds an mTLS client. The node's certificate is always
// verified against the CA.
func NewClient(p Profile, timeout time.Duration) (*Client, error) {
	if p.URL == "" || p.Cert == "" || p.Key == "" || p.CA == "" {
		return nil, errors.New("a profile needs url, cert, key and ca (heainctl profile add)")
	}
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("url %q: https://host:port is needed", p.URL)
	}
	pair, err := tls.LoadX509KeyPair(p.Cert, p.Key)
	if err != nil {
		return nil, fmt.Errorf("admin certificate: %w", err)
	}
	if fi, err := os.Stat(p.Key); err == nil && fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "heainctl: warning: %s is readable by others (chmod 600)\n", p.Key)
	}
	caPEM, err := os.ReadFile(p.CA)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("ca %s: no certificate", p.CA)
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: p.ServerName},
		Proxy:               nil, // the admin plane is never sent through a proxy
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Client{Base: strings.TrimRight(p.URL, "/"), Node: p.Node, HTTP: &http.Client{Transport: tr}, Timeout: timeout}, nil
}

// Path maps an admin path to the target node: with Node set, /v1/admin/X
// becomes /v1/admin/nodes/{Node}/admin/X (forwarded hop by hop by core).
func (c *Client) Path(p string) string {
	if c.Node == "" || !strings.HasPrefix(p, "/v1/admin/") || strings.HasPrefix(p, "/v1/admin/nodes/") {
		return p
	}
	return "/v1/admin/nodes/" + url.PathEscape(c.Node) + "/admin/" + strings.TrimPrefix(p, "/v1/admin/")
}

// Do sends a request; body is JSON-encoded unless it is []byte or an
// io.Reader (sent as application/octet-stream). It returns the answer's
// bytes and content type.
func (c *Client) Do(ctx context.Context, method, path string, body any) ([]byte, string, error) {
	return c.do(ctx, method, c.Path(path), body, c.Timeout)
}

// DoRaw is Do without the remote-admin rewriting.
func (c *Client) DoRaw(ctx context.Context, method, path string, body any, timeout time.Duration) ([]byte, string, error) {
	return c.do(ctx, method, path, body, timeout)
}

func (c *Client) do(ctx context.Context, method, path string, body any, timeout time.Duration) ([]byte, string, error) {
	var rd io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		rd, ct = bytes.NewReader(b), "application/octet-stream"
	case io.Reader:
		rd, ct = b, "application/octet-stream"
	case json.RawMessage:
		rd, ct = bytes.NewReader(b), "application/json"
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			return nil, "", err
		}
		rd, ct = bytes.NewReader(raw), "application/json"
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return nil, "", err
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("User-Agent", "heainctl/"+Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", &ConnError{err}
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<30))
	if err != nil {
		return nil, "", &ConnError{err}
	}
	if resp.StatusCode/100 != 2 {
		e := &APIError{Status: resp.StatusCode, Message: string(out), Body: string(out)}
		var j struct {
			Error *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(out, &j) == nil && j.Error != nil {
			e.Code, e.Message = j.Error.Code, j.Error.Message
		}
		return out, resp.Header.Get("Content-Type"), e
	}
	return out, resp.Header.Get("Content-Type"), nil
}
