package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
)

type machinesDataSource struct{ c *client }

type machinesModel struct {
	User     types.String   `tfsdk:"user"`
	Machines []machineModel `tfsdk:"machines"`
}

type machineModel struct {
	ID        types.Int64  `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	User      types.String `tfsdk:"user"`
	IPv4      types.String `tfsdk:"ipv4"`
	IPv6      types.String `tfsdk:"ipv6"`
	FQDN      types.String `tfsdk:"fqdn"`
	OS        types.String `tfsdk:"os"`
	Online    types.Bool   `tfsdk:"online"`
	ExitNode  types.Bool   `tfsdk:"exit_node"`
	Routes    []string     `tfsdk:"routes"`
	OSVersion types.String `tfsdk:"os_version"`
}

func newMachinesDataSource() datasource.DataSource { return &machinesDataSource{} }

func (d *machinesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_machines"
}

func (d *machinesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Machines on the network, e.g. to put their mesh addresses in DNS or firewall rules.",
		Attributes: map[string]schema.Attribute{
			"user": schema.StringAttribute{Optional: true, Description: "Only this user's machines."},
			"machines": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"id":         schema.Int64Attribute{Computed: true},
					"name":       schema.StringAttribute{Computed: true},
					"user":       schema.StringAttribute{Computed: true},
					"ipv4":       schema.StringAttribute{Computed: true},
					"ipv6":       schema.StringAttribute{Computed: true},
					"fqdn":       schema.StringAttribute{Computed: true},
					"os":         schema.StringAttribute{Computed: true},
					"os_version": schema.StringAttribute{Computed: true},
					"online":     schema.BoolAttribute{Computed: true},
					"exit_node":  schema.BoolAttribute{Computed: true},
					"routes":     schema.ListAttribute{Computed: true, ElementType: types.StringType},
				}},
			},
		},
	}
}

func (d *machinesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.c = configured(req.ProviderData, &resp.Diagnostics)
}

func (d *machinesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m machinesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	list, err := d.c.admin.ListNodes(ctx, call(d.c, &v1.ListNodesRequest{User: m.User.ValueString()}))
	if err != nil {
		apiError(&resp.Diagnostics, "Listing machines", err)
		return
	}
	m.Machines = []machineModel{}
	for _, n := range list.Msg.Nodes {
		mm := machineModel{ID: types.Int64Value(int64(n.Id)), Name: types.StringValue(n.Name), User: types.StringValue(n.User),
			FQDN: types.StringValue(n.Fqdn), OS: types.StringValue(n.Os), OSVersion: types.StringValue(n.OsVersion),
			Online: types.BoolValue(n.Online), ExitNode: types.BoolValue(n.ExitNode), Routes: n.Routes,
			IPv4: types.StringValue(""), IPv6: types.StringValue("")}
		if mm.Routes == nil {
			mm.Routes = []string{}
		}
		if len(n.Addresses) > 0 {
			mm.IPv4 = types.StringValue(n.Addresses[0])
		}
		if len(n.Addresses) > 1 {
			mm.IPv6 = types.StringValue(n.Addresses[1])
		}
		m.Machines = append(m.Machines, mm)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
