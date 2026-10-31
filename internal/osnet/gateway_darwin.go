package osnet

import (
	"bufio"
	"bytes"
	"errors"
	"net/netip"
	"os/exec"
	"strings"
)

func defaultGateway() (netip.Addr, error) {
	out, err := exec.Command("route", "-n", "get", "-inet", "default").Output()
	if err != nil {
		return netip.Addr{}, err
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && k == "gateway" {
			return netip.ParseAddr(strings.TrimSpace(v))
		}
	}
	return netip.Addr{}, errors.New("no IPv4 default gateway")
}
