package provider

import (
	"context"

	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ ephemeral.EphemeralResource              = &EphemeralSecretsResource{}
	_ ephemeral.EphemeralResourceWithConfigure = &EphemeralSecretsResource{}
)

func NewEphemeralSecretsResource() ephemeral.EphemeralResource {
	return &EphemeralSecretsResource{
		typeName:   "conjur_secrets",
		capability: CapabilityBatchSecrets,
	}
}

type EphemeralSecretsResource struct {
	typeName   string
	capability Capability
	client     api.ClientV2
}

func (e *EphemeralSecretsResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secrets"
}

func (e *EphemeralSecretsResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Ephemeral secrets from CyberArk Secrets Manager, retrieved using batch secret retrieval capabilities. The secret values are NOT stored in Terraform state - they exist only during the Terraform operation.",
		Attributes: map[string]schema.Attribute{
			"names": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "list of names (paths) of the secrets (between 1 and 250 entries)",
				Validators:  namesListValidators,
			},
			"values": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Sensitive:   true,
				Description: "Map of retrieved secret values, keyed by secret name (path) as requested (the batch API echoes each requested identifier back verbatim) (not stored in state)",
			},
			"fail_on_error": schema.BoolAttribute{
				Optional: true,
				Description: "Determines whether a non-success status code in one of the retrieved secrets (or a secret missing from the response) should fail the whole read. " +
					"Defaults to true, matching the single-secret conjur_secret data source: any secret that can't be retrieved fails the read. " +
					"If set to false, only a warning is displayed for each secret that couldn't be retrieved, and that secret is omitted from values.",
			},
		},
	}
}

func (e *EphemeralSecretsResource) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	clients, ok := configureEphemeralClient(req, resp, e.capability, e.typeName)
	if !ok {
		return
	}
	e.client = clients.conjurClient
}

// Open retrieves the secret values via batch retrieval. This is called during each
// Terraform operation and the values are NOT stored in state - they exist only
// during the operation.
func (e *EphemeralSecretsResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	data, ok := batchRetrieveSecretsToMap(ctx, e.client, req.Config, &resp.Diagnostics)
	if !ok {
		return
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
	tflog.Trace(ctx, "opened ephemeral secrets resource")
}
