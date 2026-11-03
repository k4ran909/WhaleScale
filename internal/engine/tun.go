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
	// intercept takes packets this node answers itself (MagicDNS), which
	// then don't go to WireGuard.
	intercept func(pkt []byte) bool
}

func (t *filteredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		pkt := bufs[i][offset : offset+sizes[i]]
		if t.intercept != nil && t.intercept(pkt) {
			sizes[i] = 0 // WireGuard skips empty packets
			continue
		}
		t.f.Outbound(pkt)
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
