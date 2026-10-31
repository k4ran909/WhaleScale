package osnet

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// defaultGateway reads /proc/net/route: the row with destination 0 and the
// RTF_GATEWAY flag, lowest metric first.
func defaultGateway() (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	defer f.Close()
	const rtfGateway = 0x2
	best, bestMetric := netip.Addr{}, -1
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 7 || fl[1] != "00000000" {
			continue
		}
		flags, _ := strconv.ParseUint(fl[3], 16, 32)
		if flags&rtfGateway == 0 {
			continue
		}
		raw, err := hex.DecodeString(fl[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], binary.LittleEndian.Uint32(raw))
		metric, _ := strconv.Atoi(fl[6])
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = netip.AddrFrom4(a), metric
		}
	}
	if !best.IsValid() {
		return best, errors.New("no IPv4 default route")
	}
	return best, nil
}
