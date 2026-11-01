package osinfo

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func version() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}
