package osinfo

import "golang.org/x/sys/unix"

func version() string {
	v, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return ""
	}
	return v
}
