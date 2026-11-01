// Package provider implements the Whalescale Terraform provider.
package provider

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
)

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &whalescaleProvider{version: version} }
}

type whalescaleProvider struct{ version string }

type providerModel struct {
	ServerURL types.String `tfsdk:"server_url"`
	APIKey    types.String `tfsdk:"api_key"`
}

// client is what resources get: the admin API and the key to call it with.
type client struct {
	admin whalescalev1connect.AdminServiceClient
	key   string
}

func call[T any](c *client, msg *T) *connect.Request[T] {
	r := connect.NewRequest(msg)
	r.Header().Set("Authorization", "Bearer "+c.key)
	return r
}

// apiError turns an admin API error into a diagnostic.
func apiError(diags *diag.Diagnostics, what string, err error) {
	var ce *connect.Error
	if errors.As(err, &ce) {
		diags.AddError(what, ce.Message())
		return
	}
	diags.AddError(what, err.Error())
}

func notFound(err error) bool { return connect.CodeOf(err) == connect.CodeNotFound }

func (p *whalescaleProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "whalescale"
	resp.Version = p.version
}

func (p *whalescaleProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Whalescale mesh VPN through its admin API.",
		Attributes: map[string]schema.Attribute{
			"server_url": schema.StringAttribute{
				Optional:    true,
				Description: "The server's public URL, e.g. https://ws.example.com. Defaults to $WHALESCALE_SERVER.",
			},
			"api_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "An admin API key (whalescale apikeys create). Defaults to $WS_API_KEY.",
			},
		},
	}
}

func (p *whalescaleProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	server, key := os.Getenv("WHALESCALE_SERVER"), os.Getenv("WS_API_KEY")
	if !cfg.ServerURL.IsNull() && !cfg.ServerURL.IsUnknown() {
		server = cfg.ServerURL.ValueString()
	}
	if !cfg.APIKey.IsNull() && !cfg.APIKey.IsUnknown() {
		key = cfg.APIKey.ValueString()
	}
	if server == "" || key == "" {
		resp.Diagnostics.AddError("Missing configuration",
			"Set server_url and api_key in the provider block, or $WHALESCALE_SERVER and $WS_API_KEY.")
		return
	}
	c := &client{
		admin: whalescalev1connect.NewAdminServiceClient(&http.Client{Timeout: 30 * time.Second}, strings.TrimRight(server, "/")),
		key:   key,
	}
	who, err := c.admin.WhoAmI(ctx, call(c, &v1.WhoAmIRequest{}))
	if err != nil {
		apiError(&resp.Diagnostics, "Can't reach the Whalescale admin API", err)
		return
	}
	if who.Msg.Scope != "admin" {
		resp.Diagnostics.AddWarning("Read-only API key",
			"This key can read but not change anything: plans work, applies will be refused.")
	}
	resp.ResourceData, resp.DataSourceData = c, c
}

func (p *whalescaleProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newPolicyResource, newUserResource, newPreAuthKeyResource, newRouteApprovalResource}
}

func (p *whalescaleProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newMachinesDataSource}
}

// configured fetches the client resources and data sources were given.
func configured(data any, diags *diag.Diagnostics) *client {
	if data == nil {
		return nil // not configured yet (validation runs before Configure)
	}
	c, ok := data.(*client)
	if !ok {
		diags.AddError("Unexpected provider data", "This is a bug in the provider.")
	}
	return c
}
