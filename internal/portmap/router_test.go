package portmap

import (
	"context"
	"os"
	"testing"

	"github.com/k4ran909/whalescale/internal/osnet"
)

// TestProbeRealRouter asks this machine's router what it supports. It only
// sends read-only queries (no mapping is created) and runs only with
// WS_PROBE_ROUTER=1.
func TestProbeRealRouter(t *testing.T) {
	if os.Getenv("WS_PROBE_ROUTER") == "" {
		t.Skip("set WS_PROBE_ROUTER=1 to query the real router")
	}
	gw, local, err := osnet.DefaultGateway()
	if err != nil {
		t.Skipf("no default gateway: %v", err)
	}
	rep := Probe(context.Background(), Config{Gateway: gw, Local: local, Port: 41641})
	t.Logf("pcp=%v nat-pmp=%v upnp=%v external_is_public=%v double_nat=%v err=%q",
		rep.PCP, rep.NATPMP, rep.UPnP, rep.ExternalIP.IsValid() && isPublic(rep.ExternalIP), rep.DoubleNAT, rep.Error)
}
