package meshconn

import (
	"net"
	"sync/atomic"
)

var addrsFunc atomic.Pointer[func() ([]net.Addr, error)]

// SetInterfaceAddrs replaces net.InterfaceAddrs for finding this machine's
// local endpoints and noticing network changes. Android 11 and later refuse
// it to apps, so the app passes in what its ConnectivityManager reports.
// nil restores net.InterfaceAddrs.
func SetInterfaceAddrs(f func() ([]net.Addr, error)) {
	if f == nil {
		addrsFunc.Store(nil)
		return
	}
	addrsFunc.Store(&f)
}

func interfaceAddrs() ([]net.Addr, error) {
	if f := addrsFunc.Load(); f != nil {
		return (*f)()
	}
	return net.InterfaceAddrs()
}
