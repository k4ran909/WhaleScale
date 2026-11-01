package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
)

type tool struct {
	name, title, description string
	params                   []param
	// write: changes something (needs an admin key); destructive: can
	// remove access or data.
	write, destructive bool
	run                func(ctx context.Context, s *Server, a *args) (string, error)
}

type param struct {
	name, kind, description string // kind: string, boolean, integer
	required                bool
}

func (t *tool) describe() map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, p := range t.params {
		props[p.name] = map[string]any{"type": p.kind, "description": p.description}
		if p.required {
			required = append(required, p.name)
		}
	}
	return map[string]any{
		"name":        t.name,
		"title":       t.title,
		"description": t.description,
		"inputSchema": map[string]any{"type": "object", "properties": props, "required": required},
		"annotations": map[string]any{
			"title":           t.title,
			"readOnlyHint":    !t.write,
			"destructiveHint": t.destructive,
			"openWorldHint":   false,
		},
	}
}

// args reads tool arguments, remembering the first problem.
type args struct {
	m   map[string]any
	err error
}

func argReader(m map[string]any) *args { return &args{m: m} }

func (a *args) str(name string, required bool) string {
	v, ok := a.m[name]
	if !ok || v == nil {
		if required && a.err == nil {
			a.err = fmt.Errorf("missing argument %q", name)
		}
		return ""
	}
	s, ok := v.(string)
	if !ok && a.err == nil {
		a.err = fmt.Errorf("argument %q must be a string", name)
	}
	return s
}

func (a *args) boolean(name string) bool {
	b, _ := a.m[name].(bool)
	return b
}

func (a *args) num(name string) uint64 {
	if f, ok := a.m[name].(float64); ok && f > 0 {
		return uint64(f)
	}
	return 0
}

var pjson = protojson.MarshalOptions{UseProtoNames: true}

func asJSON(m proto.Message) string { return pjson.Format(m) }

// nodeID finds a machine by name or numeric ID.
func nodeID(ctx context.Context, s *Server, name string) (uint64, error) {
	resp, err := s.admin.ListNodes(ctx, authed(s, connect.NewRequest(&v1.ListNodesRequest{})))
	if err != nil {
		return 0, err
	}
	for _, n := range resp.Msg.Nodes {
		if n.Name == name || fmt.Sprint(n.Id) == name {
			return n.Id, nil
		}
	}
	return 0, fmt.Errorf("no machine named %q", name)
}

var tools = []*tool{
	{
		name: "whoami", title: "Who am I",
		description: "Shows which API key the tools act as and its scope (admin, or read-only).",
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.WhoAmI(ctx, authed(s, connect.NewRequest(&v1.WhoAmIRequest{})))
			if err != nil {
				return "", err
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "list_machines", title: "List machines",
		description: "Lists machines on the network: name, owner, mesh addresses, OS and client version, online state, routes.",
		params:      []param{{"user", "string", "only this user's machines", false}},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.ListNodes(ctx, authed(s, connect.NewRequest(&v1.ListNodesRequest{User: a.str("user", false)})))
			if err != nil {
				return "", err
			}
			// The keys and endpoints are noise for an agent.
			for _, n := range r.Msg.Nodes {
				n.MachineKey, n.NodeKey, n.DiscoKey, n.Endpoints, n.SshHostKey, n.LockSignature = "", "", "", nil, "", nil
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "list_users", title: "List users",
		description: "Lists users, their email and how many machines each has (and their device limit, if any).",
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.ListUsers(ctx, authed(s, connect.NewRequest(&v1.ListUsersRequest{})))
			if err != nil {
				return "", err
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "get_policy", title: "Get access policy",
		description: "Returns the access policy in force (JSON with groups, acls, ssh, postures, access_requests, " +
			"device_limits and tests) and where it comes from (database, file or Git URL).",
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.GetPolicy(ctx, authed(s, connect.NewRequest(&v1.GetPolicyRequest{})))
			if err != nil {
				return "", err
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "check_policy", title: "Check a policy",
		description: "Validates a draft access policy without applying it: syntax errors, its own tests, and warnings " +
			"such as users that don't exist.",
		params: []param{{"policy", "string", "the policy JSON", true}},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.CheckPolicy(ctx, authed(s, connect.NewRequest(&v1.CheckPolicyRequest{Policy: a.str("policy", true)})))
			if err != nil {
				return "", err
			}
			if len(r.Msg.Errors) == 0 {
				return "valid\n" + asJSON(r.Msg), nil
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "explain_access", title: "Explain access",
		description: "Says whether a source can reach a destination port and why: the rule that allows it, or the " +
			"near misses (wrong port, wrong source, failed device posture). Sources are a user, node:NAME or an IP; " +
			"destinations are the same followed by :PORT. Pass policy to test a draft.",
		params: []param{
			{"src", "string", "user, node:NAME or IP", true},
			{"dst", "string", "user, node:NAME or IP, then :PORT (e.g. node:nas:445)", true},
			{"policy", "string", "optional draft policy JSON to evaluate instead of the one in force", false},
		},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.ExplainAccess(ctx, authed(s, connect.NewRequest(&v1.ExplainAccessRequest{
				Src: a.str("src", true), Dst: a.str("dst", true), Policy: a.str("policy", false)})))
			if err != nil {
				return "", err
			}
			verdict := "DENIED"
			if r.Msg.Allowed {
				verdict = "ALLOWED"
			}
			return verdict + "\n- " + strings.Join(r.Msg.Reasons, "\n- "), nil
		},
	},
	{
		name: "list_routes", title: "List subnet routes",
		description: "Lists subnet and exit-node routes machines advertise, and whether each is approved.",
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.ListRoutes(ctx, authed(s, connect.NewRequest(&v1.ListRoutesRequest{})))
			if err != nil {
				return "", err
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "topology", title: "Connection topology",
		description: "Shows how machines currently reach each other: direct, through a peer relay or through the server relay, with latency.",
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.GetTopology(ctx, authed(s, connect.NewRequest(&v1.GetTopologyRequest{})))
			if err != nil {
				return "", err
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "query_flows", title: "Connection logs",
		description: "Shows recent connections (flow logs, if the server has them on): who connected to whom on which " +
			"port, bytes, and refused attempts.",
		params: []param{
			{"machine", "string", "only connections this machine reported", false},
			{"since_minutes", "integer", "how far back (default 60)", false},
			{"denied_only", "boolean", "only attempts the policy refused", false},
			{"limit", "integer", "maximum rows (default 100)", false},
		},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			limit := a.num("limit")
			if limit == 0 {
				limit = 100
			}
			r, err := s.admin.QueryFlows(ctx, authed(s, connect.NewRequest(&v1.QueryFlowsRequest{Node: a.str("machine", false),
				SinceSeconds: a.num("since_minutes") * 60, DeniedOnly: a.boolean("denied_only"), Limit: uint32(limit)})))
			if err != nil {
				return "", err
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "list_audit_events", title: "Audit log",
		description: "Lists who changed what (users, machines, keys, approvals, policy, sign-ins), newest first.",
		params: []param{
			{"since_hours", "integer", "how far back (default: everything)", false},
			{"actor", "string", "only actors containing this", false},
			{"action", "string", "only actions containing this", false},
			{"limit", "integer", "maximum rows (default 100)", false},
		},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			limit := a.num("limit")
			if limit == 0 {
				limit = 100
			}
			r, err := s.admin.ListAuditEvents(ctx, authed(s, connect.NewRequest(&v1.ListAuditEventsRequest{
				SinceSeconds: a.num("since_hours") * 3600, Actor: a.str("actor", false), Action: a.str("action", false), Limit: uint32(limit)})))
			if err != nil {
				return "", err
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "list_access_requests", title: "Access requests",
		description: "Lists temporary access requests waiting for a decision and grants in force (or all, with include_closed).",
		params:      []param{{"include_closed", "boolean", "also decided, revoked and expired requests", false}},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.ListAccessRequests(ctx, authed(s, connect.NewRequest(&v1.ListAccessRequestsRequest{IncludeClosed: a.boolean("include_closed")})))
			if err != nil {
				return "", err
			}
			return asJSON(r.Msg), nil
		},
	},

	// --- changes (admin keys only) ---
	{
		name: "set_policy", title: "Apply an access policy", write: true, destructive: true,
		description: "Replaces the access policy with this JSON. It is refused if invalid or if it fails its own tests; " +
			"run check_policy first. Not available when the policy comes from a file or Git.",
		params: []param{{"policy", "string", "the complete policy JSON", true}},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.SetPolicy(ctx, authed(s, connect.NewRequest(&v1.SetPolicyRequest{Policy: a.str("policy", true)})))
			if err != nil {
				return "", err
			}
			return "policy applied\n" + asJSON(r.Msg), nil
		},
	},
	{
		name: "set_route_approved", title: "Approve or withdraw a route", write: true,
		description: "Approves (or withdraws approval of) a subnet or exit-node route a machine advertises.",
		params: []param{
			{"machine", "string", "machine name", true},
			{"prefix", "string", "the route, e.g. 192.168.1.0/24 or 0.0.0.0/0", true},
			{"approved", "boolean", "true to approve, false to withdraw", true},
		},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			id, err := nodeID(ctx, s, a.str("machine", true))
			if err != nil {
				return "", err
			}
			_, err = s.admin.SetRouteApproved(ctx, authed(s, connect.NewRequest(&v1.SetRouteApprovedRequest{
				NodeId: id, Prefix: a.str("prefix", true), Approved: a.boolean("approved")})))
			if err != nil {
				return "", err
			}
			return "done", nil
		},
	},
	{
		name: "decide_access_request", title: "Approve or deny an access request", write: true,
		description: "Approves or denies a pending temporary access request (see list_access_requests).",
		params: []param{
			{"id", "integer", "request ID", true},
			{"approve", "boolean", "true to approve, false to deny", true},
		},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.DecideAccess(ctx, authed(s, connect.NewRequest(&v1.DecideAccessRequest{Id: a.num("id"), Approve: a.boolean("approve")})))
			if err != nil {
				return "", err
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "revoke_access", title: "Revoke a temporary grant", write: true, destructive: true,
		description: "Ends an active temporary access grant early.",
		params:      []param{{"id", "integer", "request ID", true}},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			if _, err := s.admin.RevokeAccess(ctx, authed(s, connect.NewRequest(&v1.RevokeAccessRequest{Id: a.num("id")}))); err != nil {
				return "", err
			}
			return "revoked", nil
		},
	},
	{
		name: "create_preauth_key", title: "Create a pre-auth key", write: true,
		description: "Creates a key that adds machines to the network as this user (ws login --authkey). The secret " +
			"is shown once; treat it like a password.",
		params: []param{
			{"user", "string", "the user new machines belong to", true},
			{"reusable", "boolean", "usable for more than one machine", false},
			{"ephemeral", "boolean", "machines are removed when they go offline", false},
			{"expires_hours", "integer", "validity (default 24)", false},
		},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			r, err := s.admin.CreatePreAuthKey(ctx, authed(s, connect.NewRequest(&v1.CreatePreAuthKeyRequest{
				User: a.str("user", true), Reusable: a.boolean("reusable"), Ephemeral: a.boolean("ephemeral"),
				ExpirationSeconds: uint64((time.Duration(a.num("expires_hours")) * time.Hour).Seconds())})))
			if err != nil {
				return "", err
			}
			return asJSON(r.Msg), nil
		},
	},
	{
		name: "delete_machine", title: "Remove a machine", write: true, destructive: true,
		description: "Removes a machine from the network. It has to log in again to come back.",
		params:      []param{{"machine", "string", "machine name", true}},
		run: func(ctx context.Context, s *Server, a *args) (string, error) {
			id, err := nodeID(ctx, s, a.str("machine", true))
			if err != nil {
				return "", err
			}
			if _, err := s.admin.DeleteNode(ctx, authed(s, connect.NewRequest(&v1.DeleteNodeRequest{Id: id}))); err != nil {
				return "", err
			}
			return "removed", nil
		},
	},
}
