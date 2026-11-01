package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
)

type preAuthKeyResource struct{ c *client }

type preAuthKeyModel struct {
	ID         types.String `tfsdk:"id"`
	User       types.String `tfsdk:"user"`
	Reusable   types.Bool   `tfsdk:"reusable"`
	Ephemeral  types.Bool   `tfsdk:"ephemeral"`
	Expiration types.String `tfsdk:"expiration"`
	Key        types.String `tfsdk:"key"`
	ExpiresAt  types.String `tfsdk:"expires_at"`
}

func newPreAuthKeyResource() resource.Resource { return &preAuthKeyResource{} }

func (r *preAuthKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_preauth_key"
}

func (r *preAuthKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replaceBool := []planmodifier.Bool{boolplanmodifier.RequiresReplace()}
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		Description: "A key that adds machines as a user (ws login --authkey), e.g. for provisioning servers. " +
			"Destroying it expires the key; machines it added stay.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The key's public prefix.", PlanModifiers: keep},
			"user": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"reusable": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false), PlanModifiers: replaceBool,
				Description: "Usable for more than one machine.",
			},
			"ephemeral": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false), PlanModifiers: replaceBool,
				Description: "Machines it adds are removed when they go offline.",
			},
			"expiration": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("24h"),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Description:   "How long the key is valid, as a Go duration (\"24h\", \"720h\").",
			},
			"key": schema.StringAttribute{
				Computed: true, Sensitive: true, PlanModifiers: keep,
				Description: "The secret to pass to ws login --authkey.",
			},
			"expires_at": schema.StringAttribute{Computed: true, PlanModifiers: keep, Description: "RFC 3339."},
		},
	}
}

func (r *preAuthKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = configured(req.ProviderData, &resp.Diagnostics)
}

func (r *preAuthKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m preAuthKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ttl, err := time.ParseDuration(m.Expiration.ValueString())
	if err != nil || ttl <= 0 {
		resp.Diagnostics.AddAttributeError(pathOf("expiration"), "Bad expiration", "Use a positive duration like \"24h\".")
		return
	}
	out, err := r.c.admin.CreatePreAuthKey(ctx, call(r.c, &v1.CreatePreAuthKeyRequest{User: m.User.ValueString(),
		Reusable: m.Reusable.ValueBool(), Ephemeral: m.Ephemeral.ValueBool(), ExpirationSeconds: uint64(ttl / time.Second)}))
	if err != nil {
		apiError(&resp.Diagnostics, "Creating pre-auth key", err)
		return
	}
	m.ID = types.StringValue(out.Msg.Key.Prefix)
	m.Key = types.StringValue(out.Msg.Secret)
	m.ExpiresAt = types.StringValue(out.Msg.Key.ExpiresAt.AsTime().UTC().Format(time.RFC3339))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *preAuthKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m preAuthKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	list, err := r.c.admin.ListPreAuthKeys(ctx, call(r.c, &v1.ListPreAuthKeysRequest{}))
	if err != nil {
		apiError(&resp.Diagnostics, "Reading pre-auth keys", err)
		return
	}
	for _, k := range list.Msg.Keys {
		if k.Prefix == m.ID.ValueString() {
			// The secret can't be read back; the state keeps it.
			m.User, m.Reusable, m.Ephemeral = types.StringValue(k.User), types.BoolValue(k.Reusable), types.BoolValue(k.Ephemeral)
			resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}

func (r *preAuthKeyResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces a replacement.
}

func (r *preAuthKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m preAuthKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, err := r.c.admin.ExpirePreAuthKey(ctx, call(r.c, &v1.ExpirePreAuthKeyRequest{Prefix: m.ID.ValueString()})); err != nil && !notFound(err) {
		apiError(&resp.Diagnostics, "Expiring pre-auth key", err)
	}
}
