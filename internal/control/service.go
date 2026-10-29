// Package control implements the ControlService that nodes talk to.
package control

import (
	"context"
	"encoding/base64"
	"errors"
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
}

type Service struct {
	store *store.Store
	log   *slog.Logger
	cfg   Config

	policyMu sync.RWMutex
	policy   *policy.Policy

	version atomic.Uint64

	mu     sync.Mutex
	subs   map[uint64]map[chan struct{}]bool // node ID -> stream wake-ups
	online map[uint64]int
}

var _ whalescalev1connect.ControlServiceHandler = (*Service)(nil)

func New(s *store.Store, log *slog.Logger, cfg Config) *Service {
	if cfg.DNSSuffix == "" {
		cfg.DNSSuffix = "whale.internal"
	}
	svc := &Service{store: s, log: log, cfg: cfg, policy: policy.AllowAll(),
		subs: map[uint64]map[chan struct{}]bool{}, online: map[uint64]int{}}
	svc.version.Store(1)
	return svc
}

// SetPolicy swaps in a new policy and pushes fresh maps to every node.
func (s *Service) SetPolicy(p *policy.Policy) {
	s.policyMu.Lock()
	s.policy = p
	s.policyMu.Unlock()
	s.NotifyAll()
}

// NotifyAll wakes every open stream to send a new network map.
func (s *Service) NotifyAll() {
	s.version.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, chans := range s.subs {
		for ch := range chans {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

func (s *Service) Register(ctx context.Context, req *connect.Request[v1.RegisterRequest]) (*connect.Response[v1.RegisterResponse], error) {
	m := req.Msg
	if m.AuthKey == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("auth_key is required"))
	}
	if err := validateKey(m.MachineKey); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("machine_key: "+err.Error()))
	}
	node, token, err := s.store.RegisterNode(ctx, store.RegisterParams{
		AuthKey:    m.AuthKey,
		MachineKey: m.MachineKey,
		Hostname:   m.Hostname,
		OS:         truncate(m.Os, 32),
	})
	switch {
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
	s.log.Info("node registered", "id", node.ID, "name", node.Name, "user", node.User, "ipv4", node.IPv4)
	s.NotifyAll()
	return connect.NewResponse(&v1.RegisterResponse{Node: s.toProto(node), NodeToken: token}), nil
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
	changed, err := s.store.UpdateNodeInfo(ctx, self.ID, store.NodeInfo{
		NodeKey: m.NodeKey, DiscoKey: m.DiscoKey, Endpoints: m.Endpoints, OS: truncate(m.Os, 32),
	})
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
	nm, err := s.buildMap(ctx, self.ID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.GetNetworkMapResponse{Self: nm.Self, Peers: nm.Peers}), nil
}

func (s *Service) StreamNetworkMap(ctx context.Context, req *connect.Request[v1.StreamNetworkMapRequest], stream *connect.ServerStream[v1.StreamNetworkMapResponse]) error {
	self, err := s.authenticate(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return err
	}
	wake := make(chan struct{}, 1)
	s.mu.Lock()
	if s.subs[self.ID] == nil {
		s.subs[self.ID] = map[chan struct{}]bool{}
	}
	s.subs[self.ID][wake] = true
	s.online[self.ID]++
	firstStream := s.online[self.ID] == 1
	s.mu.Unlock()
	if firstStream {
		s.NotifyAll() // peers learn we're online
	}
	defer func() {
		s.mu.Lock()
		delete(s.subs[self.ID], wake)
		s.online[self.ID]--
		gone := s.online[self.ID] == 0
		if gone {
			delete(s.online, self.ID)
			delete(s.subs, self.ID)
		}
		s.mu.Unlock()
		if gone {
			s.NotifyAll()
		}
	}()

	send := func() error {
		nm, err := s.buildMap(ctx, self.ID)
		if err != nil {
			return err
		}
		return stream.Send(&v1.StreamNetworkMapResponse{NetworkMap: nm})
	}
	if err := send(); err != nil {
		return err
	}
	t := time.NewTicker(keepAliveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
			if err := send(); err != nil {
				return err
			}
		case <-t.C:
			if err := stream.Send(&v1.StreamNetworkMapResponse{KeepAlive: true}); err != nil {
				return err
			}
		}
	}
}

// buildMap computes the network map for one node under the current policy.
func (s *Service) buildMap(ctx context.Context, selfID uint64) (*v1.NetworkMap, error) {
	all, err := s.store.ListNodes(ctx, "")
	if err != nil {
		s.log.Error("list nodes", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	pnodes := make([]policy.Node, len(all))
	var self *store.Node
	for i := range all {
		n := &all[i]
		pnodes[i] = policy.Node{ID: n.ID, Name: n.Name, User: n.User, Addrs: []netip.Addr{n.IPv4, n.IPv6}}
		if n.ID == selfID {
			self = n
		}
	}
	if self == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("node was deleted"))
	}
	s.policyMu.RLock()
	compiled := s.policy.Compile(pnodes)
	s.policyMu.RUnlock()

	nm := &v1.NetworkMap{
		Self:    s.toProto(self),
		Dns:     &v1.DNSConfig{Suffix: s.cfg.DNSSuffix},
		Relays:  s.cfg.Relays,
		Stun:    s.cfg.STUN,
		Version: s.version.Load(),
		// An empty, non-nil filter means deny-all inbound.
		PacketFilter: []*v1.FilterRule{},
	}
	for i := range all {
		n := &all[i]
		if n.ID != selfID && compiled.Peers[selfID][n.ID] {
			nm.Peers = append(nm.Peers, s.toProto(n))
		}
	}
	for _, r := range compiled.Rules[selfID] {
		fr := &v1.FilterRule{}
		for _, p := range r.Src {
			fr.SrcPrefixes = append(fr.SrcPrefixes, p.String())
		}
		for _, pr := range r.Ports {
			fr.Ports = append(fr.Ports, &v1.PortRange{First: uint32(pr.First), Last: uint32(pr.Last)})
		}
		nm.PacketFilter = append(nm.PacketFilter, fr)
	}
	return nm, nil
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
	return &v1.Node{
		Id:         n.ID,
		Name:       n.Name,
		User:       n.User,
		MachineKey: n.MachineKey,
		Addresses:  []string{n.IPv4.String(), n.IPv6.String()},
		Os:         n.OS,
		CreatedAt:  timestamppb.New(n.CreatedAt),
		LastSeen:   timestamppb.New(n.LastSeen),
		Ephemeral:  n.Ephemeral,
		NodeKey:    n.NodeKey,
		DiscoKey:   n.DiscoKey,
		Endpoints:  n.Endpoints,
		Online:     online,
		Fqdn:       n.Name + "." + s.cfg.DNSSuffix,
	}
}
