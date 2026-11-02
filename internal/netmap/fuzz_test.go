package netmap

import (
	"testing"

	"google.golang.org/protobuf/proto"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
)

// Deltas come from the control server: a malformed one must be refused or
// applied, never crash the client.
func FuzzApply(f *testing.F) {
	cur, _ := proto.Marshal(&v1.NetworkMap{Version: 3, Self: &v1.Node{Id: 1, Name: "a"},
		Peers: []*v1.Node{{Id: 2, Name: "b"}, {Id: 3, Name: "c"}}})
	delta, _ := proto.Marshal(&v1.NetworkMapDelta{Version: 4,
		PeersChanged: []*v1.Node{{Id: 2, Name: "b2"}}, PeersRemoved: []uint64{3}})
	f.Add(cur, delta)
	f.Add(cur, []byte{})
	f.Fuzz(func(t *testing.T, curB, deltaB []byte) {
		var m v1.NetworkMap
		var d v1.NetworkMapDelta
		if proto.Unmarshal(curB, &m) != nil || proto.Unmarshal(deltaB, &d) != nil {
			return
		}
		next, err := Apply(&m, &d)
		if err == nil && next == nil {
			t.Fatal("no map and no error")
		}
		Apply(nil, &d)
	})
}
