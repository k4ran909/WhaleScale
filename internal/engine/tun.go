package engine

import (
	"golang.zx2c4.com/wireguard/tun"

	"github.com/k4ran909/whalescale/internal/filter"
)

// filteredTUN applies the packet filter between WireGuard and the OS:
// Read carries packets leaving this node, Write carries decrypted packets
// arriving from peers.
type filteredTUN struct {
	tun.Device
	f *filter.Filter
}

func (t *filteredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		t.f.Outbound(bufs[i][offset : offset+sizes[i]])
	}
	return n, err
}

func (t *filteredTUN) Write(bufs [][]byte, offset int) (int, error) {
	allowed := make([][]byte, 0, len(bufs))
	for _, b := range bufs {
		if t.f.Inbound(b[offset:]) {
			allowed = append(allowed, b)
		}
	}
	if len(allowed) > 0 {
		if _, err := t.Device.Write(allowed, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}
