package control

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Settings are the server settings an admin can change in the console while
// the server runs. The config file gives their starting values; a value
// saved in the console (in the database, so every server sharing it agrees)
// overrides it until reset.
type Settings struct {
	FlowLogs      bool
	PostQuantum   bool
	GatewayDomain string
}

// Setting names, the same as the config file's keys.
const (
	SettingFlowLogs      = "flow-logs"
	SettingPostQuantum   = "post-quantum"
	SettingGatewayDomain = "gateway-domain"
)

// SettingNames lists the settings the console can change.
var SettingNames = []string{SettingFlowLogs, SettingPostQuantum, SettingGatewayDomain}

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// NormalizeSetting checks a value for setting name and returns it in the
// form it's stored in.
func NormalizeSetting(name, value string) (string, error) {
	value = strings.TrimSpace(value)
	switch name {
	case SettingFlowLogs, SettingPostQuantum:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return "", fmt.Errorf("%s: want true or false", name)
		}
		return strconv.FormatBool(b), nil
	case SettingGatewayDomain:
		value = strings.Trim(strings.ToLower(value), ".")
		if value != "" && !domainRe.MatchString(value) {
			return "", fmt.Errorf("%s: %q is not a domain name like apps.example.com", name, value)
		}
		return value, nil
	}
	return "", fmt.Errorf("unknown setting %q", name)
}

// apply sets setting name (already normalized) on st.
func (st *Settings) apply(name, value string) {
	switch name {
	case SettingFlowLogs:
		st.FlowLogs = value == "true"
	case SettingPostQuantum:
		st.PostQuantum = value == "true"
	case SettingGatewayDomain:
		st.GatewayDomain = value
	}
}

// configSettings is what the config file says.
func (s *Service) configSettings() Settings {
	return Settings{FlowLogs: s.cfg.FlowLogs, PostQuantum: s.cfg.PostQuantum, GatewayDomain: s.cfg.GatewayDomain}
}

// Settings returns the settings in effect.
func (s *Service) Settings() Settings {
	if p := s.live.Load(); p != nil {
		return *p
	}
	return s.configSettings()
}

// ConfigSettings returns the config file's values, before console changes.
func (s *Service) ConfigSettings() Settings { return s.configSettings() }

// SetOnSettings registers f, called with the settings in effect whenever
// they change (the gateway follows its domain this way). Call before
// ReloadSettings.
func (s *Service) SetOnSettings(f func(Settings)) { s.onSettings = f }

// ReloadSettings reads the settings saved in the console and applies them,
// pushing fresh maps to every node if anything changed. It returns the
// names saved in the console. Servers sharing a database call it now and
// then to pick up each other's changes.
func (s *Service) ReloadSettings(ctx context.Context) (map[string]bool, error) {
	saved, err := s.store.ConsoleSettings(ctx)
	if err != nil {
		return nil, err
	}
	st := s.configSettings()
	overridden := map[string]bool{}
	for _, name := range SettingNames {
		v, ok := saved[name]
		if !ok {
			continue
		}
		if v, err = NormalizeSetting(name, v); err != nil {
			s.log.Warn("ignoring a bad console setting", "setting", name, "err", err)
			continue
		}
		st.apply(name, v)
		overridden[name] = true
	}
	s.settingsMu.Lock()
	prev := s.Settings()
	changed := s.live.Load() == nil || prev != st
	s.live.Store(&st)
	s.settingsMu.Unlock()
	if changed {
		if s.onSettings != nil {
			s.onSettings(st)
		}
		if prev != st {
			s.log.Info("settings changed", "flow-logs", st.FlowLogs, "post-quantum", st.PostQuantum, "gateway-domain", st.GatewayDomain)
			s.NotifyAll()
		}
	}
	return overridden, nil
}

// SaveSetting stores a console change to setting name ("" value with reset
// returns it to the config file's) and applies it.
func (s *Service) SaveSetting(ctx context.Context, name, value string, reset bool) error {
	if reset {
		if !slices.Contains(SettingNames, name) {
			return fmt.Errorf("unknown setting %q", name)
		}
		if err := s.store.DeleteConsoleSetting(ctx, name); err != nil {
			return err
		}
	} else {
		v, err := NormalizeSetting(name, value)
		if err != nil {
			return err
		}
		if err := s.store.SetConsoleSetting(ctx, name, v); err != nil {
			return err
		}
	}
	_, err := s.ReloadSettings(ctx)
	return err
}
