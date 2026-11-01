// Package control implements the ControlService that nodes talk to.
package control

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/key"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/store"
)

const keepAliveInterval = 30 * time.Second

// Config is what the server tells every node about the network.
type Config struct {
	DNSSuffix string
	Relays    []string // e.g. wss://ws.example.com/relay
	STUN      []string // host:port
	// PublicURL is used to build browser login links.
	PublicURL string
	// OIDC reports whether browser login is configured.
	OIDC bool
	// GatewayDomain enables the gateway: exposures are published at
	// https://<name>.<GatewayDomain>. GatewayURL is the tunnel endpoint.
	GatewayDomain string
	GatewayURL    string
	// GatewayConnected reports whether a node holds a gateway tunnel.
	GatewayConnected func(nodeID uint64) bool
	// RecordingsDir stores recorded SSH sessions.
	RecordingsDir string
	// FlowLogs makes nodes report connection activity.
	FlowLogs bool
	// QUICRelay (host:port) and its certificate pin (hex), if offered.
	QUICRelay, QUICRelayPin string
}

type Service struct {
	store *store.Store
	log   *slog.Logger
	cfg   Config

	policyMu     sync.RWMutex
	policy       *policy.Policy
	policyText   string
	policySource string // "default", "database", "file" or "url"
	policyStatus func() PolicyStatus

	version atomic.Uint64
	// storeDirty means stored node data may have changed since the last
	// snapshot read it. Policy pushes and online changes don't set it, so
	// they skip the database entirely.
	storeDirty atomic.Bool

	snapMu sync.Mutex
	snap   *snapshot

	mu sync.Mutex
	// changed is closed and replaced on every change: one broadcast wakes
	// every stream, at a cost that doesn't grow with the network.
	changed chan struct{}
	online  map[uint64]int
	paths   map[uint64]pathSet // node ID -> latest report
	pending map[string]*pendingReg
	taken   map[uint64][]string // exposure names a node asked for but another holds

	stats Stats
}

type pathSet struct {
	reports []*v1.PathReport
	at      time.Time
}

// Stats are counters exported as metrics.
type Stats struct {
	Registrations atomic.Uint64
	MapsSent      atomic.Uint64
	// Snapshots counts network snapshots built (one per batch of changes).
	Snapshots atomic.Uint64
	// Compiles counts policy compilations; endpoint changes don't cause one.
	Compiles atomic.Uint64
}

// pendingReg is a node registration waiting for a browser login.
type pendingReg struct {
	params  store.RegisterParams
	created time.Time
	done    chan struct{}
	node    *store.Node
	token   string
	err     error
}

var _ whalescalev1connect.ControlServiceHandler = (*Service)(nil)

func New(s *store.Store, log *slog.Logger, cfg Config) *Service {
	if cfg.DNSSuffix == "" {
		cfg.DNSSuffix = "whale.internal"
	}
	svc := &Service{store: s, log: log, cfg: cfg, policy: policy.AllowAll(), policySource: "default",
		changed: make(chan struct{}), online: map[uint64]int{},
		paths: map[uint64]pathSet{}, pending: map[string]*pendingReg{}, taken: map[uint64][]string{}}
	svc.version.Store(1)
	svc.storeDirty.Store(true)
	return svc
}

// SetPolicy swaps in a new policy and pushes fresh maps to every node.
// source is "default", "database" or "file"; text is shown in the console.
func (s *Service) SetPolicy(p *policy.Policy, text, source string) {
	s.policyMu.Lock()
	s.policy, s.policyText, s.policySource = p, text, source
	s.policyMu.Unlock()
	s.notify(false)
}

// PolicyStatus describes a policy synced from a URL.
type PolicyStatus struct {
	URL      string
	LastSync time.Time
	Revision string
	Error    string
}

// SetPolicyStatus registers where sync status comes from.
func (s *Service) SetPolicyStatus(f func() PolicyStatus) {
	s.policyMu.Lock()
	s.policyStatus = f
	s.policyMu.Unlock()
}

// Audit records an action in the audit log (and the server log). A failure
// to record is logged; the action itself has already happened.
func (s *Service) Audit(ctx context.Context, actor, action string, kv ...any) {
	s.log.Info("audit: "+action, append([]any{"by", actor}, kv...)...)
	if err := s.store.Audit(context.WithoutCancel(ctx), actor, action, kv...); err != nil {
		s.log.Error("write audit log", "err", err, "action", action)
	}
}

// deviceLimit applies the current policy's device limits.
func (s *Service) deviceLimit(user string) (int, bool) {
	return s.CurrentPolicy().DeviceLimit(user)
}

// CurrentPolicy returns the active policy.
func (s *Service) CurrentPolicy() *policy.Policy {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.policy
}

// Policy returns the active policy's text and source.
func (s *Service) Policy() (text, source string) {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.policyText, s.policySource
}

// NotifyAll tells every open stream that stored data changed, so each
// node gets whatever part of the change concerns it.
func (s *Service) NotifyAll() { s.notify(true) }

// notify starts a new map version and wakes every stream. storeChanged
// says whether the database must be read again.
func (s *Service) notify(storeChanged bool) {
	if storeChanged {
		s.storeDirty.Store(true)
	}
	s.version.Add(1)
	s.mu.Lock()
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
}

// changes returns a channel that is closed at the next NotifyAll.
func (s *Service) changes() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}

func (s *Service) Register(ctx context.Context, req *connect.Request[v1.RegisterRequest]) (*connect.Response[v1.RegisterResponse], error) {
	m := req.Msg
	if err := validateKey(m.MachineKey); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("machine_key: "+err.Error()))
	}
	if m.AuthKey == "" {
		return s.startBrowserRegistration(m)
	}
	node, token, err := s.store.RegisterNode(ctx, store.RegisterParams{
		AuthKey:     m.AuthKey,
		MachineKey:  m.MachineKey,
		Hostname:    m.Hostname,
		OS:          truncate(m.Os, 32),
		DeviceLimit: s.deviceLimit,
	})
	var limitErr *store.DeviceLimitError
	switch {
	case errors.As(err, &limitErr):
		s.Audit(ctx, "user:"+limitErr.User, "registration refused", "reason", "device limit", "limit", limitErr.Limit,
			"hostname", m.Hostname)
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, store.ErrInvalidKey):
		s.log.Warn("registration rejected", "reason", "invalid auth key", "peer", req.Peer().Addr)
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, store.ErrAlreadyExists):
		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, store.ErrPoolExhausted):
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	case err != nil:
		s.log.Error("register node", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	s.Audit(ctx, "user:"+node.User, "node registered", "node", node.Name, "ipv4", node.IPv4, "os", node.OS, "method", "pre-auth key")
	s.stats.Registrations.Add(1)
	s.NotifyAll()
	return connect.NewResponse(&v1.RegisterResponse{Node: s.toProto(node), NodeToken: token}), nil
}

const pendingTTL = 10 * time.Minute

func (s *Service) startBrowserRegistration(m *v1.RegisterRequest) (*connect.Response[v1.RegisterResponse], error) {
	if !s.cfg.OIDC {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("auth_key is required (this server has no browser login configured)"))
	}
	id, err := randomID()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.mu.Lock()
	for k, p := range s.pending {
		if time.Since(p.created) > pendingTTL {
			delete(s.pending, k)
		}
	}
	if len(s.pending) > 1000 {
		s.mu.Unlock()
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many pending logins"))
	}
	s.pending[id] = &pendingReg{
		params:  store.RegisterParams{MachineKey: m.MachineKey, Hostname: m.Hostname, OS: truncate(m.Os, 32)},
		created: time.Now(), done: make(chan struct{}),
	}
	s.mu.Unlock()
	return connect.NewResponse(&v1.RegisterResponse{
		AuthUrl:        strings.TrimRight(s.cfg.PublicURL, "/") + "/auth/node?id=" + id,
		RegistrationId: id,
	}), nil
}

// CompleteRegistration finishes a browser login for a pending registration.
func (s *Service) CompleteRegistration(ctx context.Context, id string, userID uint64) (*store.Node, error) {
	s.mu.Lock()
	p := s.pending[id]
	s.mu.Unlock()
	if p == nil || time.Since(p.created) > pendingTTL {
		return nil, errors.New("this login link has expired; run 'ws login' again")
	}
	select {
	case <-p.done:
		return p.node, p.err
	default:
	}
	params := p.params
	params.DeviceLimit = s.deviceLimit
	p.node, p.token, p.err = s.store.RegisterNodeForUser(ctx, userID, params)
	var limitErr *store.DeviceLimitError
	if errors.As(p.err, &limitErr) {
		s.Audit(ctx, "user:"+limitErr.User, "registration refused", "reason", "device limit", "limit", limitErr.Limit,
			"hostname", params.Hostname)
	}
	close(p.done)
	if p.err == nil {
		s.Audit(ctx, "user:"+p.node.User, "node registered", "node", p.node.Name, "ipv4", p.node.IPv4, "os", p.node.OS, "method", "browser login")
		s.stats.Registrations.Add(1)
		s.NotifyAll()
	}
	return p.node, p.err
}

// PendingExists reports whether a registration id is waiting for login.
func (s *Service) PendingExists(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending[id]
	return p != nil && time.Since(p.created) < pendingTTL
}

func (s *Service) WaitRegistration(ctx context.Context, req *connect.Request[v1.WaitRegistrationRequest]) (*connect.Response[v1.WaitRegistrationResponse], error) {
	s.mu.Lock()
	p := s.pending[req.Msg.RegistrationId]
	s.mu.Unlock()
	if p == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("unknown or expired registration"))
	}
	t := time.NewTimer(50 * time.Second)
	defer t.Stop()
	select {
	case <-p.done:
	case <-t.C:
		return nil, connect.NewError(connect.CodeDeadlineExceeded, errors.New("still waiting for browser login"))
	case <-ctx.Done():
		return nil, connect.NewError(connect.CodeCanceled, ctx.Err())
	}
	s.mu.Lock()
	delete(s.pending, req.Msg.RegistrationId)
	s.mu.Unlock()
	if p.err != nil {
		if errors.Is(p.err, store.ErrAlreadyExists) {
			return nil, connect.NewError(connect.CodeAlreadyExists, p.err)
		}
		var limitErr *store.DeviceLimitError
		if errors.As(p.err, &limitErr) {
			return nil, connect.NewError(connect.CodeResourceExhausted, p.err)
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("registration failed"))
	}
	return connect.NewResponse(&v1.WaitRegistrationResponse{Node: s.toProto(p.node), NodeToken: p.token}), nil
}

func (s *Service) ReportStatus(ctx context.Context, req *connect.Request[v1.ReportStatusRequest]) (*connect.Response[v1.ReportStatusResponse], error) {
	self, err := s.authenticate(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return nil, err
	}
	reports := req.Msg.Paths
	if len(reports) > 1000 {
		reports = reports[:1000]
	}
	now := timestamppb.Now()
	for _, r := range reports {
		r.FromNode, r.UpdatedAt = self.Name, now
	}
	s.mu.Lock()
	s.paths[self.ID] = pathSet{reports: reports, at: time.Now()}
	s.mu.Unlock()
	if s.cfg.FlowLogs && len(req.Msg.Flows) > 0 {
		if err := s.store.InsertFlows(ctx, flowsFromReport(self.Name, req.Msg.Flows)); err != nil {
			s.log.Error("store flow logs", "err", err)
		}
	}
	return connect.NewResponse(&v1.ReportStatusResponse{}), nil
}

// MaxRecording caps one uploaded SSH session recording.
const MaxRecording = 32 << 20

func (s *Service) UploadRecording(ctx context.Context, req *connect.Request[v1.UploadRecordingRequest]) (*connect.Response[v1.UploadRecordingResponse], error) {
	self, err := s.authenticate(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return nil, err
	}
	m := req.Msg
	if s.cfg.RecordingsDir == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this server does not store recordings"))
	}
	if len(m.Data) == 0 || len(m.Data) > MaxRecording {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("recording is empty or too large"))
	}
	// The node name comes from the authenticated node, never the request.
	r, err := s.store.SaveRecording(ctx, s.cfg.RecordingsDir, store.Recording{
		NodeName: self.Name, LocalUser: truncate(m.LocalUser, 64), SrcNode: truncate(m.SrcNode, 64),
		SrcUser: truncate(m.SrcUser, 64), StartedAt: m.StartedAt.AsTime(), EndedAt: m.EndedAt.AsTime(),
	}, m.Data)
	if err != nil {
		s.log.Error("save recording", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	s.log.Info("ssh session recorded", "node", self.Name, "local_user", r.LocalUser, "from", r.SrcNode, "bytes", r.Size)
	return connect.NewResponse(&v1.UploadRecordingResponse{}), nil
}

// maxFlowsPerReport bounds what one node can write per report.
const maxFlowsPerReport = 1000

// flowsFromReport validates reported flows. The node name always comes
// from the authenticated node.
func flowsFromReport(node string, in []*v1.FlowRecord) []store.Flow {
	if len(in) > maxFlowsPerReport {
		in = in[:maxFlowsPerReport]
	}
	var out []store.Flow
	for _, f := range in {
		c, err1 := netip.ParseAddr(f.Client)
		sv, err2 := netip.ParseAddr(f.Server)
		if err1 != nil || err2 != nil || f.Proto > 255 || f.Port > 65535 {
			continue
		}
		out = append(out, store.Flow{NodeName: node, Proto: uint8(f.Proto), Client: c.String(), Server: sv.String(),
			Port: uint16(f.Port), Outbound: f.Outbound, Denied: f.Denied, Start: f.Start.AsTime(), End: f.End.AsTime(),
			BytesSent: f.BytesSent, BytesRecv: f.BytesRecv, PacketsSent: f.PacketsSent, PacketsRecv: f.PacketsRecv})
	}
	return out
}

// Topology returns recent path reports from online nodes.
func (s *Service) Topology() []*v1.PathReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*v1.PathReport
	for id, ps := range s.paths {
		if s.online[id] == 0 || time.Since(ps.at) > 2*time.Minute {
			continue
		}
		out = append(out, ps.reports...)
	}
	return out
}

// OnlineCount reports how many nodes hold a map stream.
func (s *Service) OnlineCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.online)
}

// Stats exposes counters for metrics.
func (s *Service) Stats() *Stats { return &s.stats }

func randomID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Service) UpdateNode(ctx context.Context, req *connect.Request[v1.UpdateNodeRequest]) (*connect.Response[v1.UpdateNodeResponse], error) {
	self, err := s.authenticate(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return nil, err
	}
	m := req.Msg
	for name, k := range map[string]string{"node_key": m.NodeKey, "disco_key": m.DiscoKey} {
		if err := validateKey(k); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(name+": "+err.Error()))
		}
	}
	if len(m.Endpoints) > 32 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("too many endpoints"))
	}
	for _, ep := range m.Endpoints {
		if _, err := netip.ParseAddrPort(ep); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad endpoint "+ep))
		}
	}
	mesh6, _ := s.store.IPv6Prefix(ctx)
	routes, err := parseAdvertised(m.AdvertisedRoutes, mesh6)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	exposures, err := parseExposures(m.Exposures)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if k := m.SshHostKey; k != "" && (len(k) > 512 || !strings.HasPrefix(k, "ssh-ed25519 ")) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("ssh_host_key must be an ssh-ed25519 public key"))
	}
	changed, err := s.store.UpdateNodeInfo(ctx, self.ID, store.NodeInfo{
		NodeKey: m.NodeKey, DiscoKey: m.DiscoKey, Endpoints: m.Endpoints, OS: truncate(m.Os, 32),
		SSHHostKey: m.SshHostKey,
	})
	if err == nil {
		var rc bool
		rc, err = s.store.SetAdvertisedRoutes(ctx, self.ID, routes)
		if rc {
			s.log.Info("node routes changed", "name", self.Name, "advertised", routes)
		}
		changed = changed || rc
	}
	if err == nil {
		var oc bool
		oc, err = s.store.SetRelayOffered(ctx, self.ID, m.OfferRelay)
		if oc {
			s.log.Info("node relay offer changed", "name", self.Name, "offered", m.OfferRelay)
		}
		changed = changed || oc
	}
	if err == nil {
		var ec bool
		var taken []string
		ec, taken, err = s.store.SetExposures(ctx, self.ID, exposures)
		if ec {
			s.log.Info("node exposures changed", "name", self.Name, "count", len(exposures))
		}
		if len(taken) > 0 {
			s.log.Warn("exposure names already taken", "name", self.Name, "taken", taken)
		}
		s.mu.Lock()
		s.taken[self.ID] = taken
		s.mu.Unlock()
		changed = changed || ec
	}
	if errors.Is(err, store.ErrAlreadyExists) {
		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	}
	if err != nil {
		s.log.Error("update node", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	if changed {
		s.log.Info("node updated", "name", self.Name, "endpoints", len(m.Endpoints))
		s.NotifyAll()
	}
	return connect.NewResponse(&v1.UpdateNodeResponse{}), nil
}

func (s *Service) GetNetworkMap(ctx context.Context, req *connect.Request[v1.GetNetworkMapRequest]) (*connect.Response[v1.GetNetworkMapResponse], error) {
	self, err := s.authenticate(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return nil, err
	}
	snap, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	i, ok := snap.index[self.ID]
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("node was deleted"))
	}
	nm := fullMap(snap, i, &v1.NetworkMap{})
	return connect.NewResponse(&v1.GetNetworkMapResponse{Self: nm.Self, Peers: nm.Peers}), nil
}

func (s *Service) StreamNetworkMap(ctx context.Context, req *connect.Request[v1.StreamNetworkMapRequest], stream *connect.ServerStream[v1.StreamNetworkMapResponse]) error {
	self, err := s.authenticate(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return err
	}
	return s.runMapStream(ctx, self.ID, req.Msg.Deltas, stream.Send)
}

// runMapStream sends node id its map, then an update whenever something
// relevant to it changes, until ctx ends or send fails.
func (s *Service) runMapStream(ctx context.Context, id uint64, deltas bool, send func(*v1.StreamNetworkMapResponse) error) error {
	s.mu.Lock()
	s.online[id]++
	firstStream := s.online[id] == 1
	s.mu.Unlock()
	if firstStream {
		s.notify(false) // peers learn we're online
	}
	defer func() {
		s.mu.Lock()
		s.online[id]--
		gone := s.online[id] == 0
		if gone {
			delete(s.online, id)
		}
		s.mu.Unlock()
		if gone {
			s.notify(false)
		}
	}()

	m := &mapStream{id: id, deltas: deltas}
	// Taken before each push, so a change during the push isn't missed.
	wake := s.changes()
	push := func() error {
		snap, err := s.snapshot()
		if err != nil {
			return err
		}
		resp, err := s.next(m, snap)
		if err != nil || resp == nil {
			return err
		}
		s.stats.MapsSent.Add(1)
		pack(resp, snap)
		return send(resp)
	}
	if err := push(); err != nil {
		return err
	}
	t := time.NewTicker(keepAliveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
			wake = s.changes()
			if err := push(); err != nil {
				return err
			}
		case <-t.C:
			if err := send(&v1.StreamNetworkMapResponse{KeepAlive: true}); err != nil {
				return err
			}
		}
	}
}

// PolicyNodes converts stored nodes to what the policy engine needs.
func PolicyNodes(all []store.Node) []policy.Node {
	out := make([]policy.Node, len(all))
	for i := range all {
		n := &all[i]
		out[i] = policy.Node{ID: n.ID, Name: n.Name, User: n.User, Addrs: []netip.Addr{n.IPv4, n.IPv6}, Routes: n.Routes}
	}
	return out
}

// RelayAuth lets the relay accept a node token and learn its node key.
func (s *Service) RelayAuth(ctx context.Context, token string) (key.Public, error) {
	n, err := s.store.NodeByToken(ctx, token)
	if err != nil {
		return key.Public{}, err
	}
	return key.ParsePublic(n.NodeKey)
}

func (s *Service) authenticate(ctx context.Context, header string) (*store.Node, error) {
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || token == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing node token"))
	}
	n, err := s.store.NodeByToken(ctx, token)
	if errors.Is(err, store.ErrNotFound) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unknown node token; run 'ws login' again"))
	}
	if err != nil {
		s.log.Error("authenticate node", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	return n, nil
}

var meshRange4 = netip.MustParsePrefix("100.64.0.0/10")

func parseExposures(in []*v1.Exposure) ([]store.ExposureRequest, error) {
	if len(in) > 32 {
		return nil, errors.New("too many exposures")
	}
	var out []store.ExposureRequest
	for _, e := range in {
		if !store.ValidExposureName(e.Name) {
			return nil, fmt.Errorf("exposure name %q must be a DNS label (lowercase letters, digits, '-')", e.Name)
		}
		if e.Port == 0 || e.Port > 65535 {
			return nil, fmt.Errorf("exposure %q: bad port %d", e.Name, e.Port)
		}
		out = append(out, store.ExposureRequest{Name: e.Name, Port: uint16(e.Port)})
	}
	return out, nil
}

// exposureURL is an exposure's public address, or "" without a gateway.
func (s *Service) exposureURL(name string) string {
	if s.cfg.GatewayDomain == "" {
		return ""
	}
	return "https://" + name + "." + s.cfg.GatewayDomain
}

// parseAdvertised validates routes a node offers. Routes into the mesh's own
// ranges would loop traffic back into the tunnel, so they are refused.
func parseAdvertised(ss []string, mesh6 netip.Prefix) ([]netip.Prefix, error) {
	if len(ss) > 64 {
		return nil, errors.New("too many advertised routes")
	}
	var out []netip.Prefix
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, errors.New("bad advertised route " + s)
		}
		p = p.Masked()
		if p.Bits() > 0 {
			for _, m := range []netip.Prefix{meshRange4, mesh6} {
				if m.IsValid() && m.Overlaps(p) {
					return nil, errors.New("advertised route " + s + " overlaps the mesh's own address range")
				}
			}
		}
		out = append(out, p)
	}
	return out, nil
}

func validateKey(k string) error {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return errors.New("must be a base64-encoded 32-byte X25519 public key")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Service) toProto(n *store.Node) *v1.Node {
	s.mu.Lock()
	online := s.online[n.ID] > 0
	s.mu.Unlock()
	return s.nodeProto(n, online)
}

func (s *Service) nodeProto(n *store.Node, online bool) *v1.Node {
	var routes, advertised []string
	exit := false
	for _, r := range n.Routes {
		if r.Bits() == 0 {
			exit = true
		} else {
			routes = append(routes, r.String())
		}
	}
	for _, r := range n.AdvertisedRoutes {
		advertised = append(advertised, r.String())
	}
	return &v1.Node{
		Routes:           routes,
		AdvertisedRoutes: advertised,
		ExitNode:         exit,
		SshHostKey:       n.SSHHostKey,
		Id:               n.ID,
		Name:             n.Name,
		User:             n.User,
		MachineKey:       n.MachineKey,
		Addresses:        []string{n.IPv4.String(), n.IPv6.String()},
		Os:               n.OS,
		CreatedAt:        timestamppb.New(n.CreatedAt),
		LastSeen:         timestamppb.New(n.LastSeen),
		Ephemeral:        n.Ephemeral,
		NodeKey:          n.NodeKey,
		DiscoKey:         n.DiscoKey,
		Endpoints:        n.Endpoints,
		Online:           online,
		Fqdn:             n.Name + "." + s.cfg.DNSSuffix,
	}
}
