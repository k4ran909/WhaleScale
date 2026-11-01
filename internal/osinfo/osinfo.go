// Package osinfo reports the operating system version, for device posture.
package osinfo

// Version is the OS version as a dotted number ("10.0.22631" on Windows,
// "14.4.1" on macOS, the distribution's VERSION_ID on Linux), or "" when
// unknown.
func Version() string { return version() }
