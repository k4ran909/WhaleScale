package provider

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
)

// policyResource is the access policy: one per server.
type policyResource struct{ c *client }

type policyModel struct {
	ID       types.String `tfsdk:"id"`
	Policy   types.String `tfsdk:"policy"`
	Warnings types.List   `tfsdk:"warnings"`
}

func newPolicyResource() resource.Resource { return &policyResource{} }

func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The access policy (groups, ACLs, SSH rules, postures, access requests, device limits and tests). " +
			"There is one per server; the server refuses a policy that is invalid or fails its own tests. " +
			"Destroying this resource leaves the policy in force: Terraform just stops managing it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"policy": schema.StringAttribute{
				Required:    true,
				Description: "The policy as JSON; jsonencode() works well. Formatting differences don't cause changes.",
			},
			"warnings": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Warnings from the server, such as users the policy names that don't exist.",
			},
		},
	}
}

func (r *policyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = configured(req.ProviderData, &resp.Diagnostics)
}

func (r *policyResource) apply(ctx context.Context, m *policyModel, diags *diag.Diagnostics) bool {
	resp, err := r.c.admin.SetPolicy(ctx, call(r.c, &v1.SetPolicyRequest{Policy: m.Policy.ValueString()}))
	if err != nil {
		apiError(diags, "Policy refused", err)
		return false
	}
	m.ID = types.StringValue("policy")
	m.Warnings, _ = types.ListValueFrom(ctx, types.StringType, resp.Msg.Warnings)
	if m.Warnings.IsNull() {
		m.Warnings, _ = types.ListValueFrom(ctx, types.StringType, []string{})
	}
	return true
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || !r.apply(ctx, &m, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || !r.apply(ctx, &m, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.c.admin.GetPolicy(ctx, call(r.c, &v1.GetPolicyRequest{}))
	if err != nil {
		apiError(&resp.Diagnostics, "Reading the policy", err)
		return
	}
	// Keep the configured text when it means the same thing, so formatting
	// never shows up as a change; anything else is drift.
	if !jsonEqual(got.Msg.Policy, m.Policy.ValueString()) {
		m.Policy = types.StringValue(got.Msg.Policy)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *policyResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning("Policy left in place",
		"Whalescale always has an access policy; the current one stays in force. Terraform no longer manages it.")
}

func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func jsonEqual(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return a == b
	}
	return reflect.DeepEqual(x, y)
}
