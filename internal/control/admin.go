package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/store"
)

// SessionCookie holds a web console session token.
const SessionCookie = "ws_session"

// PolicySettingKey stores an editable policy in the settings table.
const PolicySettingKey = "policy"

// Admin implements AdminService on top of the control Service.
type Admin struct {
	svc *Service
}

var _ whalescalev1connect.AdminServiceHandler = (*Admin)(nil)

func NewAdmin(svc *Service) *Admin { return &Admin{svc: svc} }

type identity struct{ method, name string }

// auth accepts an API key bearer token, or a session cookie on requests
// that carry the Connect protocol header. Browsers can't add that header to
// cross-site form posts, so cookie auth isn't open to CSRF.
func (a *Admin) auth(ctx context.Context, h http.Header) (identity, error) {
	st := a.svc.store
	if tok, ok := strings.CutPrefix(h.Get("Authorization"), "Bearer "); ok {
		prefix, err := st.CheckAPIKey(ctx, tok)
		if err != nil {
			return identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired API key"))
		}
		return identity{"api-key", "api-key:" + prefix}, nil
	}
	if h.Get("Connect-Protocol-Version") == "" {
		return identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("missing credentials"))
	}
	req := http.Request{Header: h}
	c, err := req.Cookie(SessionCookie)
	if err != nil {
		return identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("not signed in"))
	}
	who, err := st.SessionIdentity(ctx, c.Value)
	if err != nil {
		return identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("session expired; sign in again"))
	}
	method := "oidc"
	if strings.HasPrefix(who, "api-key:") {
		method = "api-key"
	}
	return identity{method, who}, nil
}

func internal(a *Admin, what string, err error) error {
	a.svc.log.Error(what, "err", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

func notFoundOr(a *Admin, what string, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return connect.NewError(connect.CodeNotFound, err)
	}
	return internal(a, what, err)
}

func (a *Admin) audit(id identity, action string, args ...any) {
	a.svc.log.Info("admin: "+action, append([]any{"by", id.name}, args...)...)
}

func (a *Admin) WhoAmI(ctx context.Context, req *connect.Request[v1.WhoAmIRequest]) (*connect.Response[v1.WhoAmIResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.WhoAmIResponse{Method: id.method, Identity: id.name, OidcEnabled: a.svc.cfg.OIDC}), nil
}

// --- users ---

func (a *Admin) ListUsers(ctx context.Context, req *connect.Request[v1.ListUsersRequest]) (*connect.Response[v1.ListUsersResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	users, err := a.svc.store.ListUserDetails(ctx)
	if err != nil {
		return nil, internal(a, "list users", err)
	}
	resp := &v1.ListUsersResponse{}
	for _, u := range users {
		resp.Users = append(resp.Users, &v1.User{Id: u.ID, Name: u.Name, Email: u.Email,
			CreatedAt: timestamppb.New(u.CreatedAt), NodeCount: uint32(u.NodeCount)})
	}
	return connect.NewResponse(resp), nil
}

func (a *Admin) CreateUser(ctx context.Context, req *connect.Request[v1.CreateUserRequest]) (*connect.Response[v1.CreateUserResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	u, err := a.svc.store.CreateUser(ctx, req.Msg.Name)
	if errors.Is(err, store.ErrAlreadyExists) {
		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	a.audit(id, "user created", "user", u.Name)
	return connect.NewResponse(&v1.CreateUserResponse{User: &v1.User{Id: u.ID, Name: u.Name, CreatedAt: timestamppb.New(u.CreatedAt)}}), nil
}

func (a *Admin) DeleteUser(ctx context.Context, req *connect.Request[v1.DeleteUserRequest]) (*connect.Response[v1.DeleteUserResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	err = a.svc.store.DeleteUser(ctx, req.Msg.Name)
	if errors.Is(err, store.ErrUserHasNodes) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if err != nil {
		return nil, notFoundOr(a, "delete user", err)
	}
	a.audit(id, "user deleted", "user", req.Msg.Name)
	return connect.NewResponse(&v1.DeleteUserResponse{}), nil
}

// --- nodes ---

func (a *Admin) ListNodes(ctx context.Context, req *connect.Request[v1.ListNodesRequest]) (*connect.Response[v1.ListNodesResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	nodes, err := a.svc.store.ListNodes(ctx, req.Msg.User)
	if err != nil {
		return nil, internal(a, "list nodes", err)
	}
	resp := &v1.ListNodesResponse{}
	for i := range nodes {
		resp.Nodes = append(resp.Nodes, a.svc.toProto(&nodes[i]))
	}
	return connect.NewResponse(resp), nil
}

func (a *Admin) DeleteNode(ctx context.Context, req *connect.Request[v1.DeleteNodeRequest]) (*connect.Response[v1.DeleteNodeResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	if err := a.svc.store.DeleteNode(ctx, req.Msg.Id); err != nil {
		return nil, notFoundOr(a, "delete node", err)
	}
	a.audit(id, "node deleted", "node_id", req.Msg.Id)
	a.svc.NotifyAll()
	return connect.NewResponse(&v1.DeleteNodeResponse{}), nil
}

// --- pre-auth keys ---

func preAuthKeyProto(k *store.PreAuthKey) *v1.PreAuthKey {
	return &v1.PreAuthKey{Id: k.ID, Prefix: k.Prefix, User: k.User, Reusable: k.Reusable, Ephemeral: k.Ephemeral,
		Used: k.Used, ExpiresAt: timestamppb.New(k.ExpiresAt), CreatedAt: timestamppb.New(k.CreatedAt),
		Valid: time.Now().Before(k.ExpiresAt) && (k.Reusable || !k.Used)}
}

func (a *Admin) ListPreAuthKeys(ctx context.Context, req *connect.Request[v1.ListPreAuthKeysRequest]) (*connect.Response[v1.ListPreAuthKeysResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	keys, err := a.svc.store.ListPreAuthKeys(ctx)
	if err != nil {
		return nil, internal(a, "list keys", err)
	}
	resp := &v1.ListPreAuthKeysResponse{}
	for i := range keys {
		resp.Keys = append(resp.Keys, preAuthKeyProto(&keys[i]))
	}
	return connect.NewResponse(resp), nil
}

func ttl(seconds uint64, def time.Duration) time.Duration {
	if seconds == 0 {
		return def
	}
	return time.Duration(min(seconds, 10*365*24*3600)) * time.Second
}

func (a *Admin) CreatePreAuthKey(ctx context.Context, req *connect.Request[v1.CreatePreAuthKeyRequest]) (*connect.Response[v1.CreatePreAuthKeyResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	m := req.Msg
	k, secret, err := a.svc.store.CreatePreAuthKey(ctx, m.User, m.Reusable, m.Ephemeral, ttl(m.ExpirationSeconds, 24*time.Hour))
	if err != nil {
		return nil, notFoundOr(a, "create key", err)
	}
	a.audit(id, "pre-auth key created", "prefix", k.Prefix, "user", k.User, "reusable", k.Reusable)
	return connect.NewResponse(&v1.CreatePreAuthKeyResponse{Key: preAuthKeyProto(k), Secret: secret}), nil
}

func (a *Admin) ExpirePreAuthKey(ctx context.Context, req *connect.Request[v1.ExpirePreAuthKeyRequest]) (*connect.Response[v1.ExpirePreAuthKeyResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	if err := a.svc.store.ExpirePreAuthKey(ctx, req.Msg.Prefix); err != nil {
		return nil, notFoundOr(a, "expire key", err)
	}
	a.audit(id, "pre-auth key expired", "prefix", req.Msg.Prefix)
	return connect.NewResponse(&v1.ExpirePreAuthKeyResponse{}), nil
}

// --- policy ---

func (a *Admin) GetPolicy(ctx context.Context, req *connect.Request[v1.GetPolicyRequest]) (*connect.Response[v1.GetPolicyResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	text, source := a.svc.Policy()
	if source == "default" {
		text = DefaultPolicyText
	}
	return connect.NewResponse(&v1.GetPolicyResponse{Policy: text, Source: source, Editable: source != "file"}), nil
}

// DefaultPolicyText is what the editor starts from when no policy is set.
const DefaultPolicyText = `{
  "groups": {},
  "acls": [
    { "action": "accept", "src": ["*"], "dst": ["*:*"] }
  ]
}
`

func (a *Admin) check(ctx context.Context, text string) (*policy.Policy, []string, []string) {
	p, err := policy.Parse([]byte(text))
	if err != nil {
		return nil, strings.Split(err.Error(), "\n"), nil
	}
	var names []string
	if users, err := a.svc.store.ListUsers(ctx); err == nil {
		for _, u := range users {
			names = append(names, u.Name)
		}
	}
	// A policy that fails its own tests doesn't do what its author meant.
	nodes, err := a.svc.store.ListNodes(ctx, "")
	if err != nil {
		return nil, []string{"could not load nodes to run the policy's tests"}, nil
	}
	if fails := p.RunTests(PolicyNodes(nodes)); len(fails) > 0 {
		return nil, fails, p.Lint(names)
	}
	return p, nil, p.Lint(names)
}

func (a *Admin) CheckPolicy(ctx context.Context, req *connect.Request[v1.CheckPolicyRequest]) (*connect.Response[v1.CheckPolicyResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	_, errs, warns := a.check(ctx, req.Msg.Policy)
	return connect.NewResponse(&v1.CheckPolicyResponse{Errors: errs, Warnings: warns}), nil
}

func (a *Admin) SetPolicy(ctx context.Context, req *connect.Request[v1.SetPolicyRequest]) (*connect.Response[v1.SetPolicyResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	if _, source := a.svc.Policy(); source == "file" {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the policy comes from a file (--policy); edit that file instead"))
	}
	p, errs, warns := a.check(ctx, req.Msg.Policy)
	if len(errs) > 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(strings.Join(errs, "; ")))
	}
	if err := a.svc.store.SetSetting(ctx, PolicySettingKey, req.Msg.Policy); err != nil {
		return nil, internal(a, "save policy", err)
	}
	a.svc.SetPolicy(p, req.Msg.Policy, "database")
	a.audit(id, "policy updated", "acls", len(p.ACLs))
	return connect.NewResponse(&v1.SetPolicyResponse{Warnings: warns}), nil
}

func (a *Admin) ExplainAccess(ctx context.Context, req *connect.Request[v1.ExplainAccessRequest]) (*connect.Response[v1.ExplainAccessResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	p := a.svc.CurrentPolicy()
	if req.Msg.Policy != "" {
		draft, err := policy.Parse([]byte(req.Msg.Policy))
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("draft policy: %w", err))
		}
		p = draft
	}
	all, err := a.svc.store.ListNodes(ctx, "")
	if err != nil {
		return nil, internal(a, "list nodes", err)
	}
	nodes := PolicyNodes(all)
	src, err := policy.Resolve(req.Msg.Src, nodes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("from: %w", err))
	}
	dst, port, err := policy.ResolveDst(req.Msg.Dst, nodes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("to: %w", err))
	}
	ex := p.Explain(src, dst, port, nodes)
	return connect.NewResponse(&v1.ExplainAccessResponse{Allowed: ex.Allowed, Reasons: ex.Reasons}), nil
}

// --- routes ---

func (a *Admin) ListRoutes(ctx context.Context, req *connect.Request[v1.ListRoutesRequest]) (*connect.Response[v1.ListRoutesResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	routes, err := a.svc.store.ListRoutes(ctx)
	if err != nil {
		return nil, internal(a, "list routes", err)
	}
	resp := &v1.ListRoutesResponse{}
	for _, r := range routes {
		if !r.Advertised {
			continue
		}
		resp.Routes = append(resp.Routes, &v1.Route{NodeId: r.NodeID, NodeName: r.NodeName, Prefix: r.Prefix.String(),
			Approved: r.Approved, ExitNode: r.IsExit()})
	}
	return connect.NewResponse(resp), nil
}

func (a *Admin) SetRouteApproved(ctx context.Context, req *connect.Request[v1.SetRouteApprovedRequest]) (*connect.Response[v1.SetRouteApprovedResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	p, err := netip.ParsePrefix(req.Msg.Prefix)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := a.svc.store.SetRouteApproved(ctx, req.Msg.NodeId, p, req.Msg.Approved); err != nil {
		return nil, notFoundOr(a, "approve route", err)
	}
	a.audit(id, "route approval changed", "node_id", req.Msg.NodeId, "prefix", p, "approved", req.Msg.Approved)
	a.svc.NotifyAll()
	return connect.NewResponse(&v1.SetRouteApprovedResponse{}), nil
}

// --- topology ---

func (a *Admin) GetTopology(ctx context.Context, req *connect.Request[v1.GetTopologyRequest]) (*connect.Response[v1.GetTopologyResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.GetTopologyResponse{Paths: a.svc.Topology()}), nil
}

// --- peer relays ---

func (a *Admin) ListPeerRelays(ctx context.Context, req *connect.Request[v1.ListPeerRelaysRequest]) (*connect.Response[v1.ListPeerRelaysResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	nodes, err := a.svc.store.ListNodes(ctx, "")
	if err != nil {
		return nil, internal(a, "list nodes", err)
	}
	resp := &v1.ListPeerRelaysResponse{}
	for i := range nodes {
		n := &nodes[i]
		if !n.RelayOffered && !n.RelayApproved {
			continue
		}
		resp.Relays = append(resp.Relays, &v1.AdminPeerRelay{NodeId: n.ID, NodeName: n.Name,
			Approved: n.RelayApproved, Online: a.svc.toProto(n).Online})
	}
	return connect.NewResponse(resp), nil
}

func (a *Admin) SetPeerRelayApproved(ctx context.Context, req *connect.Request[v1.SetPeerRelayApprovedRequest]) (*connect.Response[v1.SetPeerRelayApprovedResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	if err := a.svc.store.SetRelayApproved(ctx, req.Msg.NodeId, req.Msg.Approved); err != nil {
		return nil, notFoundOr(a, "approve relay", err)
	}
	a.audit(id, "peer relay approval changed", "node_id", req.Msg.NodeId, "approved", req.Msg.Approved)
	a.svc.NotifyAll()
	return connect.NewResponse(&v1.SetPeerRelayApprovedResponse{}), nil
}

// --- gateway ---

func (a *Admin) ListExposures(ctx context.Context, req *connect.Request[v1.ListExposuresRequest]) (*connect.Response[v1.ListExposuresResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	list, err := a.svc.store.ListExposures(ctx)
	if err != nil {
		return nil, internal(a, "list exposures", err)
	}
	resp := &v1.ListExposuresResponse{GatewayDomain: a.svc.cfg.GatewayDomain}
	for _, e := range list {
		if !e.Advertised {
			continue
		}
		x := &v1.AdminExposure{NodeId: e.NodeID, NodeName: e.NodeName, Name: e.Name, Port: uint32(e.Port),
			Approved: e.Approved, Url: a.svc.exposureURL(e.Name)}
		if a.svc.cfg.GatewayConnected != nil {
			x.Connected = a.svc.cfg.GatewayConnected(e.NodeID)
		}
		resp.Exposures = append(resp.Exposures, x)
	}
	return connect.NewResponse(resp), nil
}

func (a *Admin) SetExposureApproved(ctx context.Context, req *connect.Request[v1.SetExposureApprovedRequest]) (*connect.Response[v1.SetExposureApprovedResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	if err := a.svc.store.SetExposureApproved(ctx, req.Msg.NodeId, req.Msg.Name, req.Msg.Approved); err != nil {
		return nil, notFoundOr(a, "approve exposure", err)
	}
	a.audit(id, "exposure approval changed", "node_id", req.Msg.NodeId, "name", req.Msg.Name, "approved", req.Msg.Approved)
	a.svc.NotifyAll()
	return connect.NewResponse(&v1.SetExposureApprovedResponse{}), nil
}

// --- flow logs ---

func (a *Admin) QueryFlows(ctx context.Context, req *connect.Request[v1.QueryFlowsRequest]) (*connect.Response[v1.QueryFlowsResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	m := req.Msg
	since := time.Hour
	if m.SinceSeconds > 0 {
		since = time.Duration(min(m.SinceSeconds, 366*24*3600)) * time.Second
	}
	limit := 200
	if m.Limit > 0 {
		limit = int(min(m.Limit, 5000))
	}
	flows, err := a.svc.store.QueryFlows(ctx, store.FlowQuery{Node: m.Node, Since: time.Now().Add(-since),
		DeniedOnly: m.DeniedOnly, Limit: limit})
	if err != nil {
		return nil, internal(a, "query flows", err)
	}
	names := map[string]string{}
	if nodes, err := a.svc.store.ListNodes(ctx, ""); err == nil {
		for _, n := range nodes {
			names[n.IPv4.String()], names[n.IPv6.String()] = n.Name, n.Name
		}
	}
	resp := &v1.QueryFlowsResponse{Enabled: a.svc.cfg.FlowLogs}
	for _, f := range flows {
		resp.Flows = append(resp.Flows, &v1.AdminFlow{NodeName: f.NodeName, Proto: uint32(f.Proto),
			Client: f.Client, ClientName: names[f.Client], Server: f.Server, ServerName: names[f.Server], Port: uint32(f.Port),
			Outbound: f.Outbound, Denied: f.Denied, Start: timestamppb.New(f.Start), End: timestamppb.New(f.End),
			BytesSent: f.BytesSent, BytesRecv: f.BytesRecv, PacketsSent: f.PacketsSent, PacketsRecv: f.PacketsRecv})
	}
	return connect.NewResponse(resp), nil
}

// --- SSH recordings ---

func recordingProto(r *store.Recording) *v1.Recording {
	return &v1.Recording{Id: r.ID, NodeName: r.NodeName, LocalUser: r.LocalUser, SrcNode: r.SrcNode, SrcUser: r.SrcUser,
		StartedAt: timestamppb.New(r.StartedAt), EndedAt: timestamppb.New(r.EndedAt), Size: uint64(r.Size)}
}

func (a *Admin) ListRecordings(ctx context.Context, req *connect.Request[v1.ListRecordingsRequest]) (*connect.Response[v1.ListRecordingsResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	list, err := a.svc.store.ListRecordings(ctx, 500)
	if err != nil {
		return nil, internal(a, "list recordings", err)
	}
	resp := &v1.ListRecordingsResponse{}
	for i := range list {
		resp.Recordings = append(resp.Recordings, recordingProto(&list[i]))
	}
	return connect.NewResponse(resp), nil
}

func (a *Admin) GetRecording(ctx context.Context, req *connect.Request[v1.GetRecordingRequest]) (*connect.Response[v1.GetRecordingResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	r, data, err := a.svc.store.RecordingByID(ctx, a.svc.cfg.RecordingsDir, req.Msg.Id)
	if err != nil {
		return nil, notFoundOr(a, "get recording", err)
	}
	a.audit(id, "recording viewed", "recording_id", r.ID, "node", r.NodeName)
	return connect.NewResponse(&v1.GetRecordingResponse{Recording: recordingProto(r), Data: data}), nil
}

// --- API keys ---

func apiKeyProto(k *store.APIKey) *v1.APIKey {
	out := &v1.APIKey{Id: k.ID, Prefix: k.Prefix, CreatedAt: timestamppb.New(k.CreatedAt),
		ExpiresAt: timestamppb.New(k.ExpiresAt), Valid: k.Valid()}
	if !k.LastUsed.IsZero() {
		out.LastUsed = timestamppb.New(k.LastUsed)
	}
	return out
}

func (a *Admin) ListAPIKeys(ctx context.Context, req *connect.Request[v1.ListAPIKeysRequest]) (*connect.Response[v1.ListAPIKeysResponse], error) {
	if _, err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	keys, err := a.svc.store.ListAPIKeys(ctx)
	if err != nil {
		return nil, internal(a, "list api keys", err)
	}
	resp := &v1.ListAPIKeysResponse{}
	for i := range keys {
		resp.Keys = append(resp.Keys, apiKeyProto(&keys[i]))
	}
	return connect.NewResponse(resp), nil
}

func (a *Admin) CreateAPIKey(ctx context.Context, req *connect.Request[v1.CreateAPIKeyRequest]) (*connect.Response[v1.CreateAPIKeyResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	k, secret, err := a.svc.store.CreateAPIKey(ctx, ttl(req.Msg.ExpirationSeconds, 90*24*time.Hour))
	if err != nil {
		return nil, internal(a, "create api key", err)
	}
	a.audit(id, "api key created", "prefix", k.Prefix)
	return connect.NewResponse(&v1.CreateAPIKeyResponse{Key: apiKeyProto(k), Secret: secret}), nil
}

func (a *Admin) ExpireAPIKey(ctx context.Context, req *connect.Request[v1.ExpireAPIKeyRequest]) (*connect.Response[v1.ExpireAPIKeyResponse], error) {
	id, err := a.auth(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	if err := a.svc.store.ExpireAPIKey(ctx, req.Msg.Prefix); err != nil {
		return nil, notFoundOr(a, "expire api key", err)
	}
	a.audit(id, "api key expired", "prefix", req.Msg.Prefix)
	return connect.NewResponse(&v1.ExpireAPIKeyResponse{}), nil
}
