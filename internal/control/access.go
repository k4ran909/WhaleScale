package control

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/store"
)

// maxPendingPerNode stops one machine from flooding admins with requests.
const maxPendingPerNode = 5

// withGrants returns base plus one ACL per active grant: from the node that
// asked, to what it was granted.
func withGrants(base *policy.Policy, grants []store.AccessRequest) *policy.Policy {
	if len(grants) == 0 {
		return base
	}
	p := *base
	p.ACLs = slices.Clip(base.ACLs)
	for _, g := range grants {
		p.ACLs = append(p.ACLs, policy.ACL{Action: "accept", Src: []string{"node:" + g.NodeName}, Dst: []string{g.Dst},
			Origin: fmt.Sprintf("temporary access #%d (until %s)", g.ID, g.ExpiresAt.Format(time.DateTime))})
	}
	return &p
}

// RefreshGrants makes the active grants part of the policy, pushing maps
// if they changed. With expire (on one server at a time) it first ends
// finished grants and stale requests. The server calls it periodically,
// which also picks up decisions made with the CLI or on other servers.
func (s *Service) RefreshGrants(ctx context.Context, expire bool) error {
	var expired []store.AccessRequest
	if expire {
		var err error
		if expired, err = s.store.ExpireAccessRequests(ctx); err != nil {
			return err
		}
	}
	for _, a := range expired {
		what := "access grant expired"
		if a.DecidedAt.IsZero() {
			what = "access request expired"
		}
		s.Audit(ctx, "system", what, "id", a.ID, "node", a.NodeName, "dst", a.Dst)
	}
	grants, err := s.store.ActiveGrants(ctx)
	if err != nil {
		return err
	}
	s.policyMu.Lock()
	same := slices.EqualFunc(grants, s.grants, func(a, b store.AccessRequest) bool { return a.ID == b.ID })
	if !same {
		s.grants = grants
		s.policy = withGrants(s.base, grants)
	}
	s.policyMu.Unlock()
	if !same {
		s.notify(false)
	}
	return nil
}

func accessProto(a *store.AccessRequest) *v1.AccessRequest {
	out := &v1.AccessRequest{Id: a.ID, NodeName: a.NodeName, User: a.User, Dst: a.Dst,
		DurationSeconds: uint64(a.Duration / time.Second), Reason: a.Reason, Status: a.Status,
		RequestedAt: timestamppb.New(a.RequestedAt), DecidedBy: a.DecidedBy}
	if !a.DecidedAt.IsZero() {
		out.DecidedAt = timestamppb.New(a.DecidedAt)
	}
	if !a.ExpiresAt.IsZero() {
		out.ExpiresAt = timestamppb.New(a.ExpiresAt)
	}
	return out
}

func policyNode(n *store.Node) policy.Node {
	return PolicyNodes([]store.Node{*n})[0]
}

func (s *Service) RequestAccess(ctx context.Context, req *connect.Request[v1.RequestAccessRequest]) (*connect.Response[v1.RequestAccessResponse], error) {
	self, err := s.authenticate(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return nil, err
	}
	a, err := s.requestAccess(ctx, self, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.RequestAccessResponse{Request: a}), nil
}

// requestAccess files a request from node self.
func (s *Service) requestAccess(ctx context.Context, self *store.Node, m *v1.RequestAccessRequest) (*v1.AccessRequest, error) {
	if len(m.Reason) > 500 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("reason is too long (500 characters at most)"))
	}
	pol := s.basePolicy()
	d := time.Duration(min(m.DurationSeconds, uint64(policy.MaxAccessDuration/time.Second))) * time.Second
	if d == 0 {
		d = max(pol.MaxRequest(policyNode(self), m.Dst), time.Minute)
	}
	rule, err := pol.MatchRequest(policyNode(self), m.Dst, d)
	if err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	}
	open, err := s.store.ListAccessRequests(ctx, store.AccessFilter{NodeID: self.ID, Open: true})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	pending := 0
	for _, a := range open {
		if a.Status == store.AccessPending {
			pending++
		}
	}
	if pending >= maxPendingPerNode {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("this machine already has requests waiting for a decision"))
	}
	a, err := s.store.CreateAccessRequest(ctx, self.ID, m.Dst, d, m.Reason, rule.AutoApprove)
	if err != nil {
		s.log.Error("create access request", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	s.Audit(ctx, "user:"+self.User, "access requested", "id", a.ID, "node", self.Name, "dst", a.Dst,
		"duration", a.Duration, "reason", a.Reason)
	if rule.AutoApprove {
		s.Audit(ctx, "policy", "access granted", "id", a.ID, "node", self.Name, "dst", a.Dst, "until", a.ExpiresAt.Format(time.RFC3339))
		s.Changed()
		if err := s.RefreshGrants(ctx, false); err != nil {
			s.log.Error("refresh grants", "err", err)
		}
	}
	return accessProto(a), nil
}

func (s *Service) ListAccess(ctx context.Context, req *connect.Request[v1.ListAccessRequest]) (*connect.Response[v1.ListAccessResponse], error) {
	self, err := s.authenticate(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return nil, err
	}
	list, err := s.store.ListAccessRequests(ctx, store.AccessFilter{NodeID: self.ID, Limit: 20})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	resp := &v1.ListAccessResponse{}
	for i := range list {
		resp.Requests = append(resp.Requests, accessProto(&list[i]))
	}
	for _, r := range s.basePolicy().Requestable(policyNode(self)) {
		for _, d := range r.Dst {
			resp.Requestable = append(resp.Requestable, &v1.RequestableAccess{Dst: d,
				MaxDurationSeconds: uint64(r.Max() / time.Second), AutoApprove: r.AutoApprove})
		}
	}
	return connect.NewResponse(resp), nil
}

// --- admin ---

func (a *Admin) ListAccessRequests(ctx context.Context, req *connect.Request[v1.ListAccessRequestsRequest]) (*connect.Response[v1.ListAccessRequestsResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	list, err := a.svc.store.ListAccessRequests(ctx, store.AccessFilter{Open: !req.Msg.IncludeClosed})
	if err != nil {
		return nil, internal(a, "list access requests", err)
	}
	resp := &v1.ListAccessRequestsResponse{}
	for i := range list {
		resp.Requests = append(resp.Requests, accessProto(&list[i]))
	}
	return connect.NewResponse(resp), nil
}

func (a *Admin) DecideAccess(ctx context.Context, req *connect.Request[v1.DecideAccessRequest]) (*connect.Response[v1.DecideAccessResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	r, err := a.svc.store.DecideAccessRequest(ctx, req.Msg.Id, req.Msg.Approve, id.actor())
	if errors.Is(err, store.ErrNotPending) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if err != nil {
		return nil, notFoundOr(a, "decide access request", err)
	}
	if r.Status == store.AccessApproved {
		a.audit(ctx, id, "access granted", "id", r.ID, "node", r.NodeName, "dst", r.Dst, "until", r.ExpiresAt.Format(time.RFC3339))
	} else {
		a.audit(ctx, id, "access denied", "id", r.ID, "node", r.NodeName, "dst", r.Dst)
	}
	a.svc.Changed()
	if err := a.svc.RefreshGrants(ctx, false); err != nil {
		return nil, internal(a, "refresh grants", err)
	}
	return connect.NewResponse(&v1.DecideAccessResponse{Request: accessProto(r)}), nil
}

func (a *Admin) RevokeAccess(ctx context.Context, req *connect.Request[v1.RevokeAccessRequest]) (*connect.Response[v1.RevokeAccessResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	r, err := a.svc.store.RevokeAccessGrant(ctx, req.Msg.Id, id.actor())
	if errors.Is(err, store.ErrNotActive) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if err != nil {
		return nil, notFoundOr(a, "revoke access grant", err)
	}
	a.audit(ctx, id, "access revoked", "id", r.ID, "node", r.NodeName, "dst", r.Dst)
	a.svc.Changed()
	if err := a.svc.RefreshGrants(ctx, false); err != nil {
		return nil, internal(a, "refresh grants", err)
	}
	return connect.NewResponse(&v1.RevokeAccessResponse{}), nil
}
