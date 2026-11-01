package netmap

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
)

// Every settings field must survive a delta without settings, so a field
// added to NetworkMap later can't be silently dropped.
func TestShallowCopyCoversAllSettings(t *testing.T) {
	fields := (&v1.NetworkMap{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		switch f.Name() {
		case "self", "peers", "packet_filter", "version":
			continue
		}
		m := (&v1.NetworkMap{}).ProtoReflect()
		switch {
		case f.IsList():
			l := m.Mutable(f).List()
			if f.Kind() == protoreflect.MessageKind {
				l.Append(l.NewElement())
			} else {
				l.Append(protoreflect.ValueOfString("x"))
			}
		case f.Kind() == protoreflect.MessageKind:
			m.Mutable(f)
		case f.Kind() == protoreflect.BoolKind:
			m.Set(f, protoreflect.ValueOfBool(true))
		case f.Kind() == protoreflect.StringKind:
			m.Set(f, protoreflect.ValueOfString("x"))
		default:
			t.Fatalf("field %s: kind %v not handled by this test", f.Name(), f.Kind())
		}
		got := shallowCopy(m.Interface().(*v1.NetworkMap))
		if !got.ProtoReflect().Has(f) {
			t.Errorf("shallowCopy drops NetworkMap.%s", f.Name())
		}
	}
}

func TestApply(t *testing.T) {
	a := &v1.Node{Id: 1, Name: "a"}
	b := &v1.Node{Id: 2, Name: "b"}
	cur := &v1.NetworkMap{Self: &v1.Node{Id: 9}, Peers: []*v1.Node{a, b}, Stun: []string{"s:3478"},
		PacketFilter: []*v1.FilterRule{{SrcPrefixes: []string{"100.64.0.1/32"}}}, Version: 1}

	next, err := Apply(cur, &v1.NetworkMapDelta{Version: 2,
		PeersChanged: []*v1.Node{{Id: 3, Name: "c"}, {Id: 1, Name: "a2"}}, PeersRemoved: []uint64{2}})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Peers) != 2 || next.Peers[0].Name != "a2" || next.Peers[1].Name != "c" {
		t.Fatalf("peers = %v", next.Peers)
	}
	if next.Version != 2 || next.Stun[0] != "s:3478" || len(next.PacketFilter) != 1 || next.Self.Id != 9 {
		t.Fatalf("unchanged parts lost: %v", next)
	}
	if len(cur.Peers) != 2 || cur.Peers[1] != b {
		t.Fatal("Apply modified its input")
	}

	// An empty filter means deny-all and must stay non-nil; settings
	// replace the rest wholesale.
	next, _ = Apply(next, &v1.NetworkMapDelta{Version: 3, PacketFilter: &v1.PacketFilter{},
		Settings: &v1.NetworkMap{Relays: []string{"wss://r"}}})
	if next.PacketFilter == nil || len(next.PacketFilter) != 0 || len(next.Stun) != 0 || next.Relays[0] != "wss://r" {
		t.Fatalf("after settings delta: %v", next)
	}
	if !proto.Equal(next.Peers[0], &v1.Node{Id: 1, Name: "a2"}) {
		t.Fatal("peers lost on a settings delta")
	}
	if _, err := Apply(nil, &v1.NetworkMapDelta{}); err == nil {
		t.Fatal("delta without a base map accepted")
	}
}
