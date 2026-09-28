package provider

import (
	"context"
	"fmt"
	"regexp"
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
	listvalidator.ValueStringsAre(
		stringvalidator.LengthAtLeast(1),
		stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must not be empty or contain only whitespace")),
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
		diags.AddError("Failed to retrieve secrets", serverErrorDetail(err))
		return data, false
	}
	if response == nil {
		diags.AddError("Failed to retrieve secrets", "empty response from server")
		return data, false
	}

	failOnError := data.FailOnError.IsNull() || data.FailOnError.IsUnknown() || data.FailOnError.ValueBool()

	if ok := checkForMismatch(names, response.Secrets, failOnError, diags); !ok {
		return data, false
	}

	requested := make(map[string]struct{}, len(names))
	for _, name := range names {
		requested[name] = struct{}{}
	}

	values := make(map[string]string, len(names))
	for _, secret := range response.Secrets {
		// values is keyed by the requested names, so callers can look up values[<name they requested>].
		// IDs that don't match a requested name verbatim (e.g. normalized or qualified IDs) are
		// dropped here; checkForMismatch reports them as unexpected and the requested names as missing.
		if _, ok := requested[secret.ID]; !ok {
			continue
		}
		if isSuccessStatus(secret.Status) {
			values[secret.ID] = secret.Value
			continue
		}

		summary := fmt.Sprintf("Failed to retrieve secret %q (status %d)", secret.ID, secret.Status)
		detail := sanitizeServerText(secret.Description)
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

// maxListedServerIDs caps how many server-supplied IDs are listed in a single diagnostic.
const maxListedServerIDs = 10

// checkForMismatch compares the requested names with the IDs in the response and adds diagnostics for:
//   - duplicate IDs in the response: always an error, since it is ambiguous which entry to use;
//   - requested secrets missing from the response: an error if failOnError is true, a warning otherwise;
//   - IDs in the response that weren't requested: a warning (these secrets are never added to values).
//
// The function returns false if an error was added to the diagnostics, and true otherwise.
func checkForMismatch(requestedNames []string, response []conjurapi.SecretValue, failOnError bool, diags *diag.Diagnostics) bool {
	requested := make(map[string]struct{}, len(requestedNames))
	for _, name := range requestedNames {
		requested[name] = struct{}{}
	}

	responseSet := make(map[string]struct{}, len(response))
	var duplicates, unexpected []string
	for _, secret := range response {
		if _, ok := responseSet[secret.ID]; ok {
			duplicates = append(duplicates, secret.ID)
			continue
		}
		responseSet[secret.ID] = struct{}{}
		if _, ok := requested[secret.ID]; !ok {
			unexpected = append(unexpected, secret.ID)
		}
	}

	if len(duplicates) > 0 {
		diags.AddError("Duplicate secrets in response", fmt.Sprintf("The response contains %d duplicate secret ID(s): %s", len(duplicates), formatServerIDs(duplicates)))
		return false
	}

	if len(unexpected) > 0 {
		diags.AddWarning("Unexpected secrets in response", fmt.Sprintf("The response contains %d secret(s) that weren't requested and were ignored: %s", len(unexpected), formatServerIDs(unexpected)))
	}

	var missing []string
	for _, name := range requestedNames {
		if _, ok := responseSet[name]; !ok {
			missing = append(missing, fmt.Sprintf("%q", name))
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

// formatServerIDs formats server-supplied secret IDs for a diagnostic: each ID is sanitized and quoted, and
// at most maxListedServerIDs are listed.
func formatServerIDs(ids []string) string {
	quoted := make([]string, 0, min(len(ids), maxListedServerIDs))
	for _, id := range ids[:min(len(ids), maxListedServerIDs)] {
		quoted = append(quoted, fmt.Sprintf("%q", sanitizeServerText(id)))
	}
	list := strings.Join(quoted, ", ")
	if len(ids) > maxListedServerIDs {
		list += fmt.Sprintf(" and %d more", len(ids)-maxListedServerIDs)
	}
	return list
}
