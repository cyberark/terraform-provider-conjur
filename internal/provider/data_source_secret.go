package provider

import (
	"context"
	"fmt"
	"log"

	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &SecretDataSource{}
	_ datasource.DataSourceWithConfigure = &SecretDataSource{}
)

func NewSecretDataSource() datasource.DataSource {
	return &SecretDataSource{}
}

type SecretDataSource struct {
	client api.ClientV2
}

type SecretDataSourceModel struct {
	Name    types.String `tfsdk:"name"`
	Version types.Int64  `tfsdk:"version"`
	Value   types.String `tfsdk:"value"`
}

// Metadata returns the resource type name.
func (d *SecretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *SecretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Secret from CyberArk Secrets Manager",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:    true,
				Description: "name (path) of the secret",
			},
			"version": schema.Int64Attribute{
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
func (d *SecretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(api.ClientV2)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected api.ClientV2, got: %T", req.ProviderData),
		)
		return
	}
	d.client = client
}

func (d *SecretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data SecretDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	nameStr := data.Name.ValueString()
	log.Printf("[DEBUG] Getting secret for name=%q", nameStr)

	var secretValue []byte
	var err error

	if !data.Version.IsNull() {
		versionInt := int(data.Version.ValueInt64())
		log.Printf("[DEBUG] Using version %d", versionInt)
		secretValue, err = d.client.RetrieveSecretWithVersion(nameStr, versionInt)
	} else {
		secretValue, err = d.client.RetrieveSecret(nameStr)
	}

	if err != nil {
		resp.Diagnostics.AddError("Failed to retrieve secret", err.Error())
		return
	}

	data.Value = types.StringValue(string(secretValue))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
