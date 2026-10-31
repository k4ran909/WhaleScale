package portmap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UPnP IGD: find the router with an SSDP search, read its device
// description, and call AddPortMapping on its WAN connection service.

var ssdpAddr = netip.MustParseAddrPort("239.255.255.250:1900")

const ssdpSearch = "M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n\r\n"

type igd struct {
	controlURL  string
	serviceType string
}

var httpClient = &http.Client{Timeout: 5 * time.Second}

// discoverIGD finds the gateway's WAN connection service. Only responses
// from the gateway itself are used, and only description URLs that point
// back at it, so another device on the LAN can't make us fetch arbitrary
// URLs. target is the SSDP address (multicast, or the fake router in tests).
func discoverIGD(ctx context.Context, gw netip.Addr, target netip.AddrPort) (*igd, error) {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.WriteToUDPAddrPort([]byte(ssdpSearch), target); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetReadDeadline(deadline)
	buf := make([]byte, 2048)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return nil, errors.New("no UPnP gateway answered")
		}
		if from.Addr().Unmap() != gw {
			continue
		}
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf[:n])), nil)
		if err != nil {
			continue
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || (loc.Scheme != "http" && loc.Scheme != "https") || loc.Hostname() != gw.String() {
			continue
		}
		dev, err := fetchDescription(ctx, loc)
		if err != nil {
			continue
		}
		return dev, nil
	}
}

type xmlDevice struct {
	DeviceType string       `xml:"deviceType"`
	Services   []xmlService `xml:"serviceList>service"`
	Devices    []xmlDevice  `xml:"deviceList>device"`
}

type xmlService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

func fetchDescription(ctx context.Context, loc *url.URL) (*igd, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", loc.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var root struct {
		URLBase string    `xml:"URLBase"`
		Device  xmlDevice `xml:"device"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&root); err != nil {
		return nil, err
	}
	base := loc
	if root.URLBase != "" {
		if u, err := url.Parse(root.URLBase); err == nil && u.Hostname() == loc.Hostname() {
			base = u
		}
	}
	var walk func(d xmlDevice) *igd
	walk = func(d xmlDevice) *igd {
		for _, s := range d.Services {
			if strings.Contains(s.ServiceType, ":WANIPConnection:") || strings.Contains(s.ServiceType, ":WANPPPConnection:") {
				u, err := base.Parse(s.ControlURL)
				if err != nil || u.Hostname() != loc.Hostname() {
					continue
				}
				return &igd{controlURL: u.String(), serviceType: s.ServiceType}
			}
		}
		for _, sub := range d.Devices {
			if g := walk(sub); g != nil {
				return g
			}
		}
		return nil
	}
	if g := walk(root.Device); g != nil {
		return g, nil
	}
	return nil, errors.New("gateway has no WAN connection service")
}

// soapError carries a UPnP error code, e.g. 725 OnlyPermanentLeasesSupported.
type soapError struct{ code int }

func (e soapError) Error() string { return fmt.Sprintf("UPnP error %d", e.code) }

func (g *igd) call(ctx context.Context, action string, args [][2]string) ([]byte, error) {
	var body strings.Builder
	body.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	fmt.Fprintf(&body, `<u:%s xmlns:u="%s">`, action, g.serviceType)
	for _, a := range args {
		fmt.Fprintf(&body, "<%s>", a[0])
		xml.EscapeText(&body, []byte(a[1]))
		fmt.Fprintf(&body, "</%s>", a[0])
	}
	fmt.Fprintf(&body, `</u:%s></s:Body></s:Envelope>`, action)
	req, err := http.NewRequestWithContext(ctx, "POST", g.controlURL, strings.NewReader(body.String()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, g.serviceType, action))
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var fault struct {
			Code int `xml:"Body>Fault>detail>UPnPError>errorCode"`
		}
		xml.Unmarshal(out, &fault)
		return nil, soapError{fault.Code}
	}
	return out, nil
}

func (g *igd) externalIP(ctx context.Context) (netip.Addr, error) {
	out, err := g.call(ctx, "GetExternalIPAddress", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	var r struct {
		IP string `xml:"Body>GetExternalIPAddressResponse>NewExternalIPAddress"`
	}
	if err := xml.Unmarshal(out, &r); err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(strings.TrimSpace(r.IP))
}

func (g *igd) addMapping(ctx context.Context, local netip.Addr, internal, external uint16, lifetime time.Duration) error {
	args := func(lease time.Duration) [][2]string {
		return [][2]string{
			{"NewRemoteHost", ""}, {"NewExternalPort", strconv.Itoa(int(external))}, {"NewProtocol", "UDP"},
			{"NewInternalPort", strconv.Itoa(int(internal))}, {"NewInternalClient", local.String()},
			{"NewEnabled", "1"}, {"NewPortMappingDescription", "whalescale"},
			{"NewLeaseDuration", strconv.Itoa(int(lease / time.Second))},
		}
	}
	_, err := g.call(ctx, "AddPortMapping", args(lifetime))
	var se soapError
	if errors.As(err, &se) && se.code == 725 { // only permanent leases: we delete it on shutdown
		_, err = g.call(ctx, "AddPortMapping", args(0))
	}
	return err
}

func (g *igd) deleteMapping(ctx context.Context, external uint16) error {
	_, err := g.call(ctx, "DeletePortMapping", [][2]string{
		{"NewRemoteHost", ""}, {"NewExternalPort", strconv.Itoa(int(external))}, {"NewProtocol", "UDP"},
	})
	return err
}
