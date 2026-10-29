// Package control implements the ControlService that nodes talk to.
package control

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/store"
)

type Service struct {
	store *store.Store
	log   *slog.Logger
}

var _ whalescalev1connect.ControlServiceHandler = (*Service)(nil)

func New(s *store.Store, log *slog.Logger) *Service {
	return &Service{store: s, log: log}
}

func (s *Service) Register(ctx context.Context, req *connect.Request[v1.RegisterRequest]) (*connect.Response[v1.RegisterResponse], error) {
	m := req.Msg
	if m.AuthKey == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("auth_key is required"))
	}
	if err := validateMachineKey(m.MachineKey); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
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
	return connect.NewResponse(&v1.RegisterResponse{Node: toProto(node), NodeToken: token}), nil
}

func (s *Service) GetNetworkMap(ctx context.Context, req *connect.Request[v1.GetNetworkMapRequest]) (*connect.Response[v1.GetNetworkMapResponse], error) {
	self, err := s.authenticate(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return nil, err
	}
	// Phase 0 has no policy engine yet: every node can see every other node.
	all, err := s.store.ListNodes(ctx, "")
	if err != nil {
		s.log.Error("list nodes", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	resp := &v1.GetNetworkMapResponse{Self: toProto(self)}
	for i := range all {
		if all[i].ID != self.ID {
			resp.Peers = append(resp.Peers, toProto(&all[i]))
		}
	}
	return connect.NewResponse(resp), nil
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

func validateMachineKey(k string) error {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return errors.New("machine_key must be a base64-encoded 32-byte X25519 public key")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func toProto(n *store.Node) *v1.Node {
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
	}
}
