// Package daemon runs the node agent: it owns the engine's lifecycle so the
// tunnel can be brought up, reconfigured and taken down without restarting
// wsd, and it serves the local API that 'ws' talks to.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"

	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/engine"
	"github.com/k4ran909/whalescale/internal/localapi"
)

type Options struct {
	StatePath string
	Userspace bool
	TUNName   string
	Port      uint16
	PortMap   bool
	Log       *slog.Logger
}

type Daemon struct {
	opts Options
	log  *slog.Logger
	ctx  context.Context

	mu  sync.Mutex
	eng *engine.Engine
	st  *clientstate.State
}

func New(opts Options) *Daemon {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Daemon{opts: opts, log: opts.Log}
}

// Run serves the local API and keeps the engine in line with the saved
// preferences until ctx is done.
func (d *Daemon) Run(ctx context.Context) error {
	d.ctx = ctx
	sock := localapi.SocketPath(d.opts.StatePath)
	ln, err := localapi.Listen(sock)
	if err != nil {
		return err
	}
	defer os.Remove(sock)
	srv := &http.Server{Handler: localapi.Handler(d)}
	go srv.Serve(ln)
	defer srv.Close()

	st, err := clientstate.Load(d.opts.StatePath)
	if err != nil {
		return err
	}
	switch {
	case st == nil || st.NodeToken == "":
		d.log.Info("not logged in yet; waiting for 'ws login' then 'ws up'", "state", d.opts.StatePath)
	case st.Prefs.Down:
		d.log.Info("tunnel is down (ws down); run 'ws up' to start it")
	default:
		if err := d.Up(st.Prefs); err != nil {
			d.log.Error("start tunnel", "err", err)
		}
	}
	d.log.Info("wsd running", "socket", sock, "userspace", d.opts.Userspace)
	<-ctx.Done()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
	return nil
}

func (d *Daemon) stopLocked() {
	if d.eng != nil {
		d.eng.Close()
		d.eng = nil
	}
}

// Engine returns the running engine, or nil while the tunnel is down.
func (d *Daemon) Engine() *engine.Engine {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.eng
}

func (d *Daemon) Prefs() clientstate.Prefs {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st == nil {
		if st, err := clientstate.Load(d.opts.StatePath); err == nil && st != nil {
			return st.Prefs
		}
		return clientstate.Prefs{}
	}
	return d.st.Prefs
}

// Up saves prefs and (re)starts the tunnel with them. It re-reads the state
// file, so a fresh 'ws login' takes effect.
func (d *Daemon) Up(p clientstate.Prefs) error {
	routes, err := ParseRoutes(p.AdvertiseRoutes)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := clientstate.Load(d.opts.StatePath)
	if err != nil {
		return err
	}
	if st == nil || st.NodeToken == "" {
		return errors.New("not logged in; run 'ws login' first")
	}
	p.Down = false
	st.Prefs = p
	if err := clientstate.Save(d.opts.StatePath, st); err != nil {
		return err
	}
	d.stopLocked()
	eng, err := engine.New(engine.Options{
		State: st, StatePath: d.opts.StatePath, Userspace: d.opts.Userspace, TUNName: d.opts.TUNName,
		Port: d.opts.Port, Log: d.log, AdvertiseRoutes: routes, AcceptRoutes: p.AcceptRoutes,
		ExitNode: p.ExitNode, Exposures: p.Exposures, OfferRelay: p.Relay, PortMap: d.opts.PortMap, SSH: p.SSH,
	})
	if err != nil {
		return err
	}
	if err := eng.Start(d.ctx); err != nil {
		return err
	}
	d.eng, d.st = eng, st
	d.log.Info("tunnel up", "node", st.NodeName, "advertise_routes", p.AdvertiseRoutes, "accept_routes", p.AcceptRoutes,
		"exit_node", p.ExitNode)
	return nil
}

// Down stops the tunnel and remembers that across restarts.
func (d *Daemon) Down() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
	st, err := clientstate.Load(d.opts.StatePath)
	if err != nil || st == nil {
		return err
	}
	st.Prefs.Down = true
	d.st = st
	d.log.Info("tunnel down")
	return clientstate.Save(d.opts.StatePath, st)
}

// ParseRoutes validates advertised routes.
func ParseRoutes(ss []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			if ip := net.ParseIP(s); ip != nil {
				return nil, fmt.Errorf("route %q needs a prefix length, e.g. %s/24", s, s)
			}
			return nil, fmt.Errorf("bad route %q", s)
		}
		if p.Masked() != p && p.Bits() != 0 {
			return nil, fmt.Errorf("route %s has host bits set; did you mean %s?", p, p.Masked())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
