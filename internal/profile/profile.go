// Package profile resolves named default {table, project, env, region}
// bundles from a user-level YAML file, so an operator working against the
// same project+env repeatedly does not have to repeat all four flags on
// every invocation.
package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Profile holds the default values a named profile supplies. Any field left
// empty simply is not applied — callers only use a Profile field as a
// fallback default for a flag/env var the caller did not otherwise set, and
// an explicitly-passed flag always takes precedence over it.
type Profile struct {
	Table   string `yaml:"table"`
	Project string `yaml:"project"`
	Env     string `yaml:"env"`
	Region  string `yaml:"region"`
}

// DefaultPath returns the default profiles file location,
// ~/.config/configctl/profiles.yaml, honouring the current $HOME.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".config", "configctl", "profiles.yaml"), nil
}

// Load reads and parses the profiles file at path, returning a map of
// profile name to Profile. A missing file is a clear error, never a silent
// empty result — the caller asked for a profile and none can be resolved.
func Load(path string) (map[string]Profile, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is resolved by DefaultPath or an operator-controlled flag, not attacker input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("profiles file not found at %s (create it or omit --profile)", path)
		}
		return nil, fmt.Errorf("read profiles file %s: %w", path, err)
	}

	var profiles map[string]Profile
	if err := yaml.Unmarshal(raw, &profiles); err != nil {
		return nil, fmt.Errorf("parse profiles file %s: %w", path, err)
	}
	return profiles, nil
}

// Resolve loads the profiles file at path and returns the named profile.
// Both a missing file and a missing name are returned as descriptive errors
// rather than a silent no-op, per the profile's job of resolving explicit
// defaults.
func Resolve(path, name string) (*Profile, error) {
	profiles, err := Load(path)
	if err != nil {
		return nil, err
	}
	p, ok := profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %q not found in %s", name, path)
	}
	return &p, nil
}
