// Package config layers settings onto a flag.FlagSet, lowest priority first:
//
//  1. flag defaults
//  2. the config file (YAML; keys are flag names)
//  3. files in conf.d/ next to it, in lexical order (package upgrades never
//     touch these, so local overrides survive them)
//  4. environment variables WHALESCALE_<FLAG> (dashes become underscores)
//  5. command-line flags
//
// Unknown keys are errors, so a typo can't silently fall back to a default.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Sources records where each setting came from, for configtest output.
type Sources map[string]string

// Load applies files and environment to fs, then parses args. path may be
// empty; a missing file at the default path is not an error.
func Load(fs *flag.FlagSet, path string, explicit bool, args []string) (Sources, error) {
	src := Sources{}
	if path != "" {
		files := []string{path}
		extra, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "conf.d", "*.yaml"))
		sort.Strings(extra)
		files = append(files, extra...)
		for i, f := range files {
			b, err := os.ReadFile(f)
			if errors.Is(err, os.ErrNotExist) && i == 0 && !explicit {
				continue
			}
			if err != nil {
				return nil, err
			}
			if err := applyYAML(fs, f, b, src); err != nil {
				return nil, err
			}
		}
	}
	var envErr error
	fs.VisitAll(func(f *flag.Flag) {
		env := "WHALESCALE_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(env); ok {
			if err := fs.Set(f.Name, v); err != nil && envErr == nil {
				envErr = fmt.Errorf("%s: %w", env, err)
			}
			src[f.Name] = "env " + env
		}
	})
	if envErr != nil {
		return nil, envErr
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	fs.Visit(func(f *flag.Flag) {
		if _, fromEnvOrFile := src[f.Name]; !fromEnvOrFile || isArg(args, f.Name) {
			src[f.Name] = "flag"
		}
	})
	return src, nil
}

func isArg(args []string, name string) bool {
	for _, a := range args {
		a = strings.TrimLeft(a, "-")
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

func applyYAML(fs *flag.FlagSet, file string, b []byte, src Sources) error {
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var errs []error
	for _, k := range keys {
		if fs.Lookup(k) == nil {
			errs = append(errs, fmt.Errorf("%s: unknown setting %q", file, k))
			continue
		}
		if err := fs.Set(k, toString(m[k])); err != nil {
			errs = append(errs, fmt.Errorf("%s: %s: %w", file, k, err))
			continue
		}
		src[k] = file
	}
	return errors.Join(errs...)
}

func toString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = fmt.Sprint(e)
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(x)
	}
}

// ConfigPath finds --config in args (before flags are parsed) and reports
// whether it was given explicitly.
func ConfigPath(args []string, def string) (string, bool) {
	for i, a := range args {
		switch {
		case a == "--config" || a == "-config":
			if i+1 < len(args) {
				return args[i+1], true
			}
		case strings.HasPrefix(a, "--config="), strings.HasPrefix(a, "-config="):
			_, v, _ := strings.Cut(a, "=")
			return v, true
		}
	}
	if v := os.Getenv("WHALESCALE_CONFIG"); v != "" {
		return v, true
	}
	return def, false
}
