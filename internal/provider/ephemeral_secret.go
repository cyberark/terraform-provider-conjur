package provider

import (
	"context"
	"fmt"
	"log"

	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ ephemeral.EphemeralResource              = &EphemeralSecretResource{}
	_ ephemeral.EphemeralResourceWithConfigure = &EphemeralSecretResource{}
)

func NewEphemeralSecretResource() ephemeral.EphemeralResource {
	return &EphemeralSecretResource{}
}

type EphemeralSecretResource struct {
	client api.ClientV2
}

type EphemeralSecretResourceModel struct {
	Name    types.String `tfsdk:"name"`
	Version types.Int64  `tfsdk:"version"`
	Value   types.String `tfsdk:"value"`
}

// Metadata returns the resource type name.
func (r *EphemeralSecretResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *EphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Ephemeral secret from CyberArk Secrets Manager. The secret value is NOT stored in Terraform state - it exists only during the Terraform operation.",
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
				Description: "value of the secret (not stored in state)",
				Sensitive:   true,
			},
		},
	}
}

// Configure adds the provider configured client to this ephemeral resource.
func (r *EphemeralSecretResource) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
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
	r.client = client
}

// Open retrieves the secret value. This is called during each Terraform operation
// and the value is NOT stored in state - it exists only during the operation.
func (r *EphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data EphemeralSecretResourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	nameStr := data.Name.ValueString()
	log.Printf("[DEBUG] Getting ephemeral secret for name=%q", nameStr)

	var secretValue []byte
	var err error

	if !data.Version.IsNull() {
		versionInt := int(data.Version.ValueInt64())
		log.Printf("[DEBUG] Using version %d", versionInt)
		secretValue, err = r.client.RetrieveSecretWithVersion(nameStr, versionInt)
	} else {
		secretValue, err = r.client.RetrieveSecret(nameStr)
	}

	if err != nil {
		resp.Diagnostics.AddError("Failed to retrieve secret", err.Error())
		return
	}

	// Set the secret value in the response data
	data.Value = types.StringValue(string(secretValue))
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
