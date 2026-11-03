package daemon

import (
	"context"
	"time"

	"github.com/k4ran909/whalescale/internal/clientstate"
)

// statusEvery is how often the public status is rewritten; a reader can
// tell wsd has stopped when it gets much older than this.
const statusEvery = 2 * time.Second

// publishStatus keeps opts.StatusFile current for the tray icon, which
// runs as an ordinary user and may not use the local API.
func (d *Daemon) publishStatus(ctx context.Context) {
	t := time.NewTicker(statusEvery)
	defer t.Stop()
	for {
		d.writeStatus("")
		select {
		case <-ctx.Done():
			d.writeStatus("stopped")
			return
		case <-t.C:
		}
	}
}

func (d *Daemon) writeStatus(state string) {
	ps := d.PublicStatus()
	if state != "" {
		ps.State, ps.Peers = state, nil
	}
	if err := clientstate.WritePublicStatus(d.opts.StatusFile, ps); err != nil {
		d.log.Debug("write public status", "err", err)
	}
}

// PublicStatus says what any local user may know: whether the tunnel is up
// and who else is on the network.
func (d *Daemon) PublicStatus() clientstate.PublicStatus {
	ps := clientstate.PublicStatus{Updated: time.Now(), State: "logged-out"}
	st, err := clientstate.Load(d.statePath())
	if err != nil || st == nil || st.NodeToken == "" {
		return ps
	}
	ps.Server, ps.Name, ps.State = st.ServerURL, st.NodeName, "down"
	eng := d.Engine()
	if eng == nil {
		return ps
	}
	s := eng.Status()
	ps.State, ps.Error = "connecting", s.LastError
	if s.Self == nil {
		return ps
	}
	ps.State, ps.Name, ps.User = "connected", s.Self.Name, s.Self.User
	if len(s.Self.Addresses) > 0 {
		ps.Address = s.Self.Addresses[0]
	}
	for _, p := range s.Peers {
		pp := clientstate.PublicPeer{Name: p.Name, OS: p.OS, Online: p.Online, Path: p.Path}
		if len(p.Addresses) > 0 {
			pp.Address = p.Addresses[0]
		}
		ps.Peers = append(ps.Peers, pp)
	}
	return ps
}
