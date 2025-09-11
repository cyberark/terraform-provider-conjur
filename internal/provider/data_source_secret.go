package provider

import (
	"context"
	"fmt"
	"log"

	"github.com/cyberark/conjur-api-go/conjurapi"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &secretDataSource{}
	_ datasource.DataSourceWithConfigure = &secretDataSource{}
)

func NewSecretDataSource() datasource.DataSource {
	return &secretDataSource{}
}

type secretDataSource struct {
	client *conjurapi.Client
}

type secretDataSourceModel struct {
	Name    types.String `tfsdk:"name"`
	Version types.String `tfsdk:"version"`
	Value   types.String `tfsdk:"value"`
}

// Metadata returns the resource type name.
func (d *secretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *secretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Secret from Conjur Vault",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:    true,
				Description: "name (path) of the secret",
			},
			"version": schema.StringAttribute{
				Optional:    true,
				Description: "version of the secret",
			},
			"value": schema.StringAttribute{
				Computed:    true,
				Description: "value of the secret",
				Sensitive:   true,
			},
		},
	}
}

// Configure adds the provider configured client to this datasource.
func (d *secretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*conjurapi.Client)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *conjurapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

// Return token
func (d *secretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data secretDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := data.Name.ValueString()
	version := data.Version.ValueString()
	log.Printf("[DEBUG] Getting secret for name=%q version=%q", name, version)

	secretValue, err := d.client.RetrieveSecret(name)
	if err != nil {
		resp.Diagnostics.AddError("Failed to retrieve secret", err.Error())
		return
	}

	data.Value = types.StringValue(string(secretValue))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
