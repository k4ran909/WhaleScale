package store

import (
	"context"
	"strings"
)

// Console settings are server settings changed in the web console. They're
// kept in the settings table under "console:<name>" and override the server
// config file's value for <name>; deleting one returns to the config file.
const consoleSettingPrefix = "console:"

// ConsoleSettings returns the settings changed in the console, by name.
func (s *Store) ConsoleSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings WHERE key LIKE 'console:%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[strings.TrimPrefix(k, consoleSettingPrefix)] = v
	}
	return out, rows.Err()
}

// SetConsoleSetting saves a setting changed in the console.
func (s *Store) SetConsoleSetting(ctx context.Context, name, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, consoleSettingPrefix+name, value)
	return err
}

// DeleteConsoleSetting returns a setting to the config file's value.
func (s *Store) DeleteConsoleSetting(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, consoleSettingPrefix+name)
	return err
}
