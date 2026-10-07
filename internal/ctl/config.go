package ctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Profile is how to reach one node as one admin identity. It names files;
// it never holds a key.
type Profile struct {
	URL        string `json:"url"`                   // https://host:port of the node's API
	Cert       string `json:"cert"`                  // the admin certificate (PEM)
	Key        string `json:"key"`                   // its private key (PEM)
	CA         string `json:"ca"`                    // the deployment's CA (PEM)
	ServerName string `json:"server_name,omitempty"` // when the URL's host is not in the node certificate
	Node       string `json:"node,omitempty"`        // a default target below this node (remote admin)
}

// Config is the profiles file.
type Config struct {
	Current  string             `json:"current,omitempty"`
	Profiles map[string]Profile `json:"profiles"`
}

// ConfigPath is $HEAINCTL_CONFIG, or ~/.config/heainctl/config.json.
func ConfigPath() string {
	if p := os.Getenv("HEAINCTL_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "heainctl", "config.json")
}

// LoadConfig reads the profiles file (an empty one when there is none).
func LoadConfig(path string) (*Config, error) {
	c := &Config{Profiles: map[string]Profile{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	return c, nil
}

// Save writes it (0600; the directory 0700).
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Names lists the profiles.
func (c *Config) Names() []string {
	var out []string
	for n := range c.Profiles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// abs makes a file path absolute, so a profile works from any directory.
func abs(p string) string {
	if p == "" {
		return p
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}
