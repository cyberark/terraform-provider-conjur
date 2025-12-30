package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/cyberark/terraform-provider-conjur/internal/policy"
	"github.com/doodlesbykumbi/conjur-policy-go/pkg/conjurpolicy"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"gopkg.in/yaml.v3"
)

const (
	// valueRWKey is the key used in private state to track whether "value" (read-write)
	// or "value_wo" (write-only) is being used. This informs the Read method to fetch
	// and store the secret value only when this key-value pair equals "true".
	valueRWKey = "value_rw"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                   = &ConjurSecretResource{}
	_ resource.ResourceWithImportState    = &ConjurSecretResource{}
	_ resource.ResourceWithConfigure      = &ConjurSecretResource{}
	_ resource.ResourceWithValidateConfig = &ConjurSecretResource{}
)

func NewConjurSecretResource() resource.Resource {
	return &ConjurSecretResource{}
}

// ConjurSecretResource defines the resource implementation.
type ConjurSecretResource struct {
	client api.ClientV2
}

type ConjurSecretResourceModel struct {
	Branch         types.String             `tfsdk:"branch"`
	Name           types.String             `tfsdk:"name"`
	MimeType       types.String             `tfsdk:"mime_type"`
	Value          types.String             `tfsdk:"value"`
	ValueWO        types.String             `tfsdk:"value_wo"`
	ValueWOVersion types.Int32              `tfsdk:"value_wo_version"`
	Annotations    map[string]string        `tfsdk:"annotations"`
	Permissions    []ConjurSecretPermission `tfsdk:"permissions"`
}

type ConjurSecretPermission struct {
	Subject    ConjurSecretSubject `tfsdk:"subject"`
	Privileges types.List          `tfsdk:"privileges"`
}

type ConjurSecretSubject struct {
	Id   types.String `tfsdk:"id"`
	Kind types.String `tfsdk:"kind"`
}

func (r *ConjurSecretResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *ConjurSecretResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "CyberArk Secrets Manager secret resource",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the secret",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"branch": schema.StringAttribute{
				MarkdownDescription: "The policy branch of the secret (must be an absolute path)",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"mime_type": schema.StringAttribute{
				MarkdownDescription: "The secret mime_type",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"value": schema.StringAttribute{
				MarkdownDescription: "The secret value",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{
					stringvalidator.PreferWriteOnlyAttribute(
						path.MatchRoot("value_wo"),
					),
				},
			},
			"value_wo": schema.StringAttribute{
				MarkdownDescription: "The secret value",
				Optional:            true,
				WriteOnly:           true,
			},
			"value_wo_version": schema.Int32Attribute{
				MarkdownDescription: "The secret value version. Used together with `value_wo` to trigger an update.",
				Optional:            true,
			},
			"permissions": schema.ListNestedAttribute{
				MarkdownDescription: "List of permissions associated with the secret",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"subject": schema.SingleNestedAttribute{
							MarkdownDescription: "The subject granted permissions",
							Optional:            true,
							Attributes: map[string]schema.Attribute{
								"id": schema.StringAttribute{
									MarkdownDescription: "Subject identifier",
									Optional:            true,
									PlanModifiers: []planmodifier.String{
										stringplanmodifier.RequiresReplace(),
									},
								},
								"kind": schema.StringAttribute{
									MarkdownDescription: "Subject kind (user, group, host, etc.)",
									Optional:            true,
									PlanModifiers: []planmodifier.String{
										stringplanmodifier.RequiresReplace(),
									},
								},
							},
						},
						"privileges": schema.ListAttribute{
							MarkdownDescription: "List of granted privileges",
							Optional:            true,
							ElementType:         types.StringType,
							PlanModifiers: []planmodifier.List{
								listplanmodifier.RequiresReplace(),
							},
						},
					},
				},
			},
			"annotations": schema.MapAttribute{
				MarkdownDescription: "Key-value annotations for the secret",
				Optional:            true,
				ElementType:         types.StringType,
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *ConjurSecretResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ConjurSecretResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data ConjurSecretResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ValidateBranch(data.Branch, &resp.Diagnostics, "branch")
	ValidateNonEmpty(data.Name, &resp.Diagnostics, "Secret name")

	// Validate that value and value_wo are mutually exclusive
	hasValue := !data.Value.IsNull() && !data.Value.IsUnknown()
	hasValueWO := !data.ValueWO.IsNull() && !data.ValueWO.IsUnknown()
	if hasValue && hasValueWO {
		resp.Diagnostics.AddError(
			"Invalid Attribute Combination",
			"Cannot set both 'value' and 'value_wo' attributes. Use 'value_wo' (write-only) to avoid storing the secret value in Terraform state, or use 'value' (read-write) to manage the secret value in state.",
		)
	}

	// Validate that value_wo_version requires value_wo
	if !data.ValueWOVersion.IsNull() && !data.ValueWOVersion.IsUnknown() {
		if data.ValueWO.IsNull() || data.ValueWO.IsUnknown() {
			resp.Diagnostics.AddError(
				"Invalid Attribute Combination",
				"The 'value_wo_version' attribute requires 'value_wo' to be set. 'value_wo_version' is used together with 'value_wo' to trigger an update.",
			)
		}
	}
}

func (r *ConjurSecretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConjurSecretResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	newSecret, err := r.buildSecretPayload(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Secret Payload", fmt.Sprintf("Could not build secret payload: %s", err))
		return
	}

	// Read value_wo from Config (write-only attributes are in Config, not Plan)
	var valueWO types.String
	diags := req.Config.GetAttribute(ctx, path.Root("value_wo"), &valueWO)
	resp.Diagnostics.Append(diags...)

	// Add an indicator to the private state to determine whether we're using value or value_wo
	if !valueWO.IsNull() {
		if resp.Private != nil {
			diags := resp.Private.SetKey(ctx, valueRWKey, []byte{})
			resp.Diagnostics.Append(diags...)
		}
		newSecret.Value = valueWO.ValueString()
	} else if !data.Value.IsNull() {
		if resp.Private != nil {
			diags := resp.Private.SetKey(ctx, valueRWKey, []byte("true"))
			resp.Diagnostics.Append(diags...)
		}
	}

	secretResp, err := r.client.CreateStaticSecret(newSecret)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create secret, got error: %s", err))
		return
	}

	// Assume permissions in the model are correct since it was just created (otherwise we would need a separate request to evaluate them)
	r.parseSecretResponse(*secretResp, conjurapi.PermissionResponse{}, &data)

	tflog.Trace(ctx, "created secret resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurSecretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConjurSecretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	secretID := fmt.Sprintf("%s/%s", data.Branch.ValueString(), data.Name.ValueString())
	secretResp, err := r.client.GetStaticSecretDetails(secretID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading Secrets Manager secret",
			fmt.Sprintf("Unable to check if secret %q exists: %s", secretID, err),
		)
		return
	}

	// TODO: Computing this in Read when permissions have been applied via a different resource, i.e. conjur_permissions or in
	// Secrets Manager directly causes there be a diff on permissions even if they are unchanged, resulting in unnecessary updates.
	// permissionResp, err := r.client.GetStaticSecretPermissions(secretID)
	// if err != nil {
	// 	resp.Diagnostics.AddError(
	// 		"Error reading Secrets Manager secret permissions",
	// 		fmt.Sprintf("Unable to check if secret %q permissions exist: %s", secretID, err),
	// 	)
	// 	return
	// }

	err = r.parseSecretResponse(*secretResp, conjurapi.PermissionResponse{}, &data)
	if err != nil {
		resp.Diagnostics.AddError("Error Parsing Secret Response", fmt.Sprintf("Could not parse secret response: %s", err))
		return
	}

	// Determine if we should fetch the secret value:
	// 1. If private state explicitly says "true" → fetch (using "value" attribute)
	// 2. If private state is missing but value is already in config → fetch (likely imported/managed)
	// 3. Otherwise → skip fetch (using "value_wo" or not managing value)
	valueRW, diags := req.Private.GetKey(ctx, valueRWKey)
	resp.Diagnostics.Append(diags...)
	hasPrivateStateMarker := len(valueRW) > 0 && string(valueRW) == "true"
	hasValueInState := !data.Value.IsNull() && !data.Value.IsUnknown()
	shouldFetchValue := hasPrivateStateMarker || (len(valueRW) == 0 && hasValueInState)

	if shouldFetchValue {
		secretValue, err := r.client.RetrieveSecret(strings.TrimPrefix(secretID, "/"))
		if err != nil {
			resp.Diagnostics.AddWarning("Unable to fetch secret value", fmt.Sprintf("Could not fetch secret value for %q: %s", secretID, err))
		} else {
			data.Value = types.StringValue(string(secretValue))
			// Set private state marker if it was missing (e.g., after import)
			if len(valueRW) == 0 && resp.Private != nil {
				diags := resp.Private.SetKey(ctx, valueRWKey, []byte("true"))
				resp.Diagnostics.Append(diags...)
			}
		}
	}

	tflog.Trace(ctx, "read secret resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Only supports rotating the secret value
func (r *ConjurSecretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ConjurSecretResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	secretID := fmt.Sprintf("%s/%s", data.Branch.ValueString(), data.Name.ValueString())

	var err error
	// Read value_wo from Config (write-only attributes are in Config, not Plan)
	var valueWO types.String
	diags := req.Config.GetAttribute(ctx, path.Root("value_wo"), &valueWO)
	resp.Diagnostics.Append(diags...)
	// Update the secret value
	if !valueWO.IsNull() {
		// Mark that we're using value_wo (write-only) so Read knows not to fetch/store the value
		if resp.Private != nil {
			diags := resp.Private.SetKey(ctx, valueRWKey, []byte{})
			resp.Diagnostics.Append(diags...)
		}
		err = r.client.AddSecret(strings.TrimPrefix(secretID, "/"), valueWO.ValueString())
	} else if !data.Value.IsNull() {
		if resp.Private != nil {
			diags := resp.Private.SetKey(ctx, valueRWKey, []byte("true"))
			resp.Diagnostics.Append(diags...)
		}
		err = r.client.AddSecret(strings.TrimPrefix(secretID, "/"), data.Value.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to set secret value", fmt.Sprintf("Could not update secret value for %q: %s", secretID, err))
	}

	tflog.Trace(ctx, "updated secret resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurSecretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConjurSecretResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deletionPolicy, err := r.generateSecretDeletionPolicy(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Secret Delete Policy", fmt.Sprintf("Could not build Secret Delete policy: %s", err))
		return
	}

	branch := strings.TrimPrefix(data.Branch.ValueString(), "/")
	err = policy.ApplyPolicy(r.client, deletionPolicy, branch)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to load Secret Delete policy, got error: %s", err))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurSecretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Split the full ID into branch and name components
	segments := strings.Split(req.ID, "/")
	if len(segments) < 2 {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			"Expected format: <branch>/<name>",
		)
		return
	}

	name := segments[len(segments)-1]
	branch := strings.Join(segments[0:len(segments)-1], "/")

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("branch"), branch)...)
}

// buildSecretPayload maps the resource model to an API payload
func (r *ConjurSecretResource) buildSecretPayload(data *ConjurSecretResourceModel) (conjurapi.StaticSecret, error) {
	// Initialize with required fields
	secret := conjurapi.StaticSecret{
		Name:   data.Name.ValueString(),
		Branch: data.Branch.ValueString(),
	}

	// Supply optional attributes only if provided
	if !data.MimeType.IsNull() && !data.MimeType.IsUnknown() {
		secret.MimeType = data.MimeType.ValueString()
	}
	if !data.Value.IsNull() && !data.Value.IsUnknown() {
		secret.Value = data.Value.ValueString()
	}
	if len(data.Permissions) > 0 {
		permissions := make([]conjurapi.Permission, len(data.Permissions))
		for i, v := range data.Permissions {
			permission := conjurapi.Permission{}
			if v.Subject.Id.ValueString() != "" && v.Subject.Kind.ValueString() != "" {
				permission.Subject = conjurapi.Subject{
					Id:   v.Subject.Id.ValueString(),
					Kind: v.Subject.Kind.ValueString(),
				}
			}
			if len(v.Privileges.Elements()) > 0 {
				privileges := make([]string, len(v.Privileges.Elements()))
				for j, p := range v.Privileges.Elements() {
					privileges[j] = p.(types.String).ValueString()
				}
				permission.Privileges = privileges
			}
			permissions[i] = permission
		}
		secret.Permissions = permissions
	}

	if len(data.Annotations) > 0 {
		secret.Annotations = data.Annotations
	}

	return secret, nil
}

func (r *ConjurSecretResource) parseSecretResponse(secretResp conjurapi.StaticSecretResponse, permissionResp conjurapi.PermissionResponse, data *ConjurSecretResourceModel) error {
	data.Name = types.StringValue(secretResp.Name)
	data.Branch = types.StringValue(secretResp.Branch)
	if secretResp.MimeType == "" {
		data.MimeType = types.StringNull()
	} else {
		data.MimeType = types.StringValue(secretResp.MimeType)
	}

	if len(permissionResp.Permission) > 0 {
		permissions := make([]ConjurSecretPermission, len(permissionResp.Permission))
		for i, v := range permissionResp.Permission {
			permission := ConjurSecretPermission{}
			if v.Subject.Id != "" && v.Subject.Kind != "" {
				permission.Subject = ConjurSecretSubject{
					Id:   types.StringValue(v.Subject.Id),
					Kind: types.StringValue(v.Subject.Kind),
				}
			}
			if len(v.Privileges) > 0 {
				privileges := make([]attr.Value, len(v.Privileges))
				for j, p := range v.Privileges {
					privileges[j] = types.StringValue(p)
				}
				permission.Privileges = types.ListValueMust(types.StringType, privileges)
			} else {
				permission.Privileges = types.ListNull(types.StringType)
			}
			permissions[i] = permission
		}
		data.Permissions = permissions
	}

	if len(secretResp.Annotations) != 0 {
		data.Annotations = secretResp.Annotations
	}

	return nil
}

func (r *ConjurSecretResource) generateSecretDeletionPolicy(data *ConjurSecretResourceModel) (string, error) {
	name := strings.TrimSpace(data.Name.ValueString())

	delete := conjurpolicy.Delete{
		Record: conjurpolicy.ResourceRef{
			Kind: conjurpolicy.KindVariable,
			Id:   name,
		},
	}

	// Create policy body with the delete statement
	policyStatements := conjurpolicy.PolicyStatements{delete}
	yamlBytes, err := yaml.Marshal(policyStatements)
	if err != nil {
		return "", fmt.Errorf("failed to marshal deletion policy to YAML: %w", err)
	}

	return string(yamlBytes), nil
}
