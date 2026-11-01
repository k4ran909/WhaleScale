package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
)

func pathOf(name string) path.Path { return path.Root(name) }

type routeApprovalResource struct{ c *client }

type routeApprovalModel struct {
	ID      types.String `tfsdk:"id"`
	Machine types.String `tfsdk:"machine"`
	Prefix  types.String `tfsdk:"prefix"`
}

func newRouteApprovalResource() resource.Resource { return &routeApprovalResource{} }

func (r *routeApprovalResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_route_approval"
}

func (r *routeApprovalResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "Approves a subnet or exit-node route a machine advertises (ws up --advertise-routes). " +
			"Destroying it withdraws the approval.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"machine": schema.StringAttribute{Required: true, PlanModifiers: replace, Description: "The machine's name."},
			"prefix": schema.StringAttribute{Required: true, PlanModifiers: replace,
				Description: "The route, e.g. 192.168.1.0/24, or 0.0.0.0/0 for an exit node."},
		},
	}
}

func (r *routeApprovalResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = configured(req.ProviderData, &resp.Diagnostics)
}

// route finds the machine's route; nil when it doesn't advertise it.
func (r *routeApprovalResource) route(ctx context.Context, machine, prefix string) (*v1.Route, error) {
	list, err := r.c.admin.ListRoutes(ctx, call(r.c, &v1.ListRoutesRequest{}))
	if err != nil {
		return nil, err
	}
	for _, rt := range list.Msg.Routes {
		if rt.NodeName == machine && rt.Prefix == prefix {
			return rt, nil
		}
	}
	return nil, nil
}

func (r *routeApprovalResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m routeApprovalModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rt, err := r.route(ctx, m.Machine.ValueString(), m.Prefix.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "Reading routes", err)
		return
	}
	if rt == nil {
		resp.Diagnostics.AddError("Route not advertised", fmt.Sprintf(
			"%s doesn't advertise %s; run 'ws up --advertise-routes %s' on it first.", m.Machine.ValueString(), m.Prefix.ValueString(), m.Prefix.ValueString()))
		return
	}
	if _, err := r.c.admin.SetRouteApproved(ctx, call(r.c, &v1.SetRouteApprovedRequest{NodeId: rt.NodeId, Prefix: rt.Prefix, Approved: true})); err != nil {
		apiError(&resp.Diagnostics, "Approving route", err)
		return
	}
	m.ID = types.StringValue(m.Machine.ValueString() + "/" + m.Prefix.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *routeApprovalResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m routeApprovalModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rt, err := r.route(ctx, m.Machine.ValueString(), m.Prefix.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "Reading routes", err)
		return
	}
	if rt == nil || !rt.Approved {
		resp.State.RemoveResource(ctx) // withdrawn elsewhere: the next apply approves it again
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *routeApprovalResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces a replacement.
}

func (r *routeApprovalResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m routeApprovalModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rt, err := r.route(ctx, m.Machine.ValueString(), m.Prefix.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "Reading routes", err)
		return
	}
	if rt == nil {
		return // the machine or route is gone already
	}
	if _, err := r.c.admin.SetRouteApproved(ctx, call(r.c, &v1.SetRouteApprovedRequest{NodeId: rt.NodeId, Prefix: rt.Prefix})); err != nil && !notFound(err) {
		apiError(&resp.Diagnostics, "Withdrawing route approval", err)
	}
}
