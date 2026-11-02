package relay

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// QUIC relay streams are length-prefixed frames from the network.
func FuzzStreamFrames(f *testing.F) {
	frame := func(n int) []byte {
		b := binary.BigEndian.AppendUint32(nil, uint32(n))
		return append(b, make([]byte, n)...)
	}
	f.Add(append(frame(40), frame(32)...))
	f.Add(binary.BigEndian.AppendUint32(nil, 1<<31))
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		total := 0
		readStreamFrames(bytes.NewReader(data), func(f []byte) {
			if len(f) > MaxPacket+32 {
				t.Fatalf("frame of %d bytes accepted", len(f))
			}
			total += 4 + len(f)
		})
		if total > len(data) {
			t.Fatalf("read %d bytes of frames from %d", total, len(data))
		}
	})
}
