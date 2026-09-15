package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &SecretsDataSource{}
	_ datasource.DataSourceWithConfigure = &SecretsDataSource{}
)

func NewSecretsDataSource() datasource.DataSource {
	return &SecretsDataSource{
		typeName:   "conjur_secrets",
		capability: CapabilityBatchSecrets,
	}
}

type SecretsDataSource struct {
	typeName   string
	capability Capability
	client     api.ClientV2
}

// secretsModel is the shared schema model for the batch secrets data source and
// ephemeral resource, which expose identical attributes.
type secretsModel struct {
	Names       types.List `tfsdk:"names"`
	Values      types.Map  `tfsdk:"values"`
	FailOnError types.Bool `tfsdk:"fail_on_error"`
}

// namesListValidators are the validators applied to the "names" attribute. The batch secrets data
// source and ephemeral resource expose an identical "names" attribute, so they share this slice to
// avoid the two schemas silently diverging on accepted input.
var namesListValidators = []validator.List{
	listvalidator.SizeBetween(1, conjurapi.MaxSecretsInSingleBatch),
	listvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1)),
	listvalidator.UniqueValues(),
}

func (s *SecretsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secrets"
}

func (s *SecretsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Secrets from CyberArk Secrets Manager. Read using batch secret retrieval capabilities.",
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
				Description: "Map of retrieved secret values, keyed by secret name (path) as requested (the batch API echoes each requested identifier back verbatim)",
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

func (s *SecretsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	clients, ok := configureDataSourceClient(req, resp, s.capability, s.typeName)
	if !ok {
		return
	}
	s.client = clients.conjurClient
}

func (s *SecretsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	data, ok := batchRetrieveSecretsToMap(ctx, s.client, req.Config, &resp.Diagnostics)
	if !ok {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	tflog.Trace(ctx, "read secrets data source")
}

// batchRetrieveSecretsToMap reads the requested secret names from config, retrieves them via
// batch secret retrieval, and returns a fully populated secretsModel whose Values map holds the
// successfully retrieved secrets. Errors and per-secret failures/warnings are appended to diags;
// ok is false when the caller should abort without writing state. It is shared by the batch
// secrets data source and the ephemeral secrets resource, which expose identical schemas.
func batchRetrieveSecretsToMap(ctx context.Context, client api.ClientV2, config tfsdk.Config, diags *diag.Diagnostics) (secretsModel, bool) {
	var data secretsModel

	if client == nil {
		AddProviderClientNotConfiguredWarning(diags)
		return data, false
	}

	// Read Terraform configuration data into the model
	diags.Append(config.Get(ctx, &data)...)
	if diags.HasError() {
		return data, false
	}

	var names []string
	diags.Append(data.Names.ElementsAs(ctx, &names, false)...)
	if diags.HasError() {
		return data, false
	}

	tflog.Debug(ctx, "Batch retrieving secrets", map[string]any{"count": len(names)})

	response, err := client.BatchRetrieveSecrets(names)
	if err != nil {
		diags.AddError("Failed to retrieve secrets", err.Error())
		return data, false
	}

	// Default to hard-fail when unset, for parity with the single-secret conjur_secret data source.
	failOnError := data.FailOnError.IsNull() || data.FailOnError.ValueBool()

	if ok := checkForMismatch(names, response.Secrets, failOnError, diags); !ok {
		return data, false
	}

	values := make(map[string]string, len(response.Secrets))
	for _, secret := range response.Secrets {
		if isSuccessStatus(secret.Status) {
			// We rely on the batch API echoing each requested identifier back verbatim as
			// secret.ID, so callers can look up values[<name they requested>]. If the server
			// ever returns normalized/qualified IDs, these map keys would diverge from the
			// requested names.
			values[secret.ID] = secret.Value
			continue
		}

		summary := fmt.Sprintf("Failed to retrieve secret %q (status %d)", secret.ID, secret.Status)
		detail := secret.Description
		if detail == "" {
			detail = fmt.Sprintf("Secret %q returned status %d", secret.ID, secret.Status)
		}
		if failOnError {
			diags.AddError(summary, detail)
		} else {
			diags.AddWarning(summary, detail)
		}
	}
	if diags.HasError() {
		return data, false
	}

	valuesMap, convDiags := types.MapValueFrom(ctx, types.StringType, values)
	diags.Append(convDiags...)
	if diags.HasError() {
		return data, false
	}
	data.Values = valuesMap

	return data, true
}

// checkForMismatch takes a list of requested names and the received ones from the response, and checks for any
// requested secrets that are missing from the response. Depending on the failOnError value, either a warning (false)
// or an error (true) will be added to the provided diagnostics if there is a mismatch. The message gives a short
// summary of the issue and which secrets are missing from the response. Any extra secrets in the response are ignored.
// The function returns false only if failOnError is true and a mismatch was found (resulting in an error added to the diagnostics).
// In all other cases it returns true.
func checkForMismatch(requestedNames []string, response []conjurapi.SecretValue, failOnError bool, diags *diag.Diagnostics) bool {
	responseSet := make(map[string]struct{}, len(response))
	for _, secret := range response {
		responseSet[secret.ID] = struct{}{}
	}

	var missing []string
	for _, name := range requestedNames {
		if _, ok := responseSet[name]; !ok {
			missing = append(missing, name)
		}
	}

	if len(missing) == 0 {
		return true
	}

	summary := "Mismatch between requested and retrieved secrets"
	detail := fmt.Sprintf("The response is missing %d of the %d requested secret(s): %s", len(missing), len(requestedNames), strings.Join(missing, ", "))
	if failOnError {
		diags.AddError(summary, detail)
		return false
	}
	diags.AddWarning(summary, detail)

	return true
}
