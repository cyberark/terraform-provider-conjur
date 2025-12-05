package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/cyberark/terraform-provider-conjur/internal/policy"
	"github.com/doodlesbykumbi/conjur-policy-go/pkg/conjurpolicy"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"gopkg.in/yaml.v3"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                     = &ConjurSecretResource{}
	_ resource.ResourceWithImportState      = &ConjurSecretResource{}
	_ resource.ResourceWithConfigure        = &ConjurSecretResource{}
	_ resource.ResourceWithValidateConfig   = &ConjurSecretResource{}
	_ resource.ResourceWithConfigValidators = &ConjurSecretResource{}
)

func NewConjurSecretResource() resource.Resource {
	return &ConjurSecretResource{}
}

// ConjurSecretResource defines the resource implementation.
type ConjurSecretResource struct {
	client api.ClientV2
}

var policyMutex sync.Mutex

type ConjurSecretResourceModel struct {
	Branch         types.String             `tfsdk:"branch"`
	Name           types.String             `tfsdk:"name"`
	MimeType       types.String             `tfsdk:"mime_type"`
	Owner          types.Object             `tfsdk:"owner"`
	Value          types.String             `tfsdk:"value"`
	ValueWO        types.String             `tfsdk:"value_wo"`
	ValueWOVersion types.Int32              `tfsdk:"value_wo_version"`
	Annotations    map[string]string        `tfsdk:"annotations"`
	Permissions    []ConjurSecretPermission `tfsdk:"permissions"`
}

type ConjurSecretPermission struct {
	Subject    ConjurSecretSubject `tfsdk:"subject"`
	Privileges types.Set           `tfsdk:"privileges"`
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
			"owner": schema.SingleNestedAttribute{
				MarkdownDescription: "Owner of the secret",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"kind": schema.StringAttribute{
						MarkdownDescription: "Owner kind (user, group, etc.)",
						Optional:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"id": schema.StringAttribute{
						MarkdownDescription: "Owner identifier",
						Optional:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
				},
			},
			"permissions": schema.SetNestedAttribute{
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
									PlanModifiers:       []planmodifier.String{
										//stringplanmodifier.RequiresReplace(),
									},
								},
								"kind": schema.StringAttribute{
									MarkdownDescription: "Subject kind (user, group, host, etc.)",
									Optional:            true,
									PlanModifiers:       []planmodifier.String{
										//stringplanmodifier.RequiresReplace(),
									},
								},
							},
						},
						"privileges": schema.SetAttribute{
							MarkdownDescription: "List of granted privileges",
							Optional:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
			"annotations": schema.MapAttribute{
				MarkdownDescription: "Key-value annotations for the secret",
				Optional:            true,
				ElementType:         types.StringType,
			},
		},
	}
}

func (r *ConjurSecretResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.PreferWriteOnlyAttribute(
			path.MatchRoot("value"),
			path.MatchRoot("value_wo"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("value"),
			path.MatchRoot("value_wo"),
		),
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

	// Ensure branch is an absolute path by adding a leading slash if necessary
	if !strings.HasPrefix(data.Branch.ValueString(), "/") {
		resp.Diagnostics.AddError(
			"Invalid branch",
			"Branch must be an absolute path including a leading slash (/).",
		)
	}

	// Warn that secret value attribute is sensitive and will be stored in state
	if !data.Value.IsNull() && !data.Value.IsUnknown() {
		resp.Diagnostics.AddWarning(
			"Sensitive Value in Configuration",
			"The 'value' attribute is marked as sensitive and will be stored in the Terraform state. Ensure your state file is securely managed.",
		)
	}
}

func (r *ConjurSecretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConjurSecretResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var valueWO types.String
	diags := req.Config.GetAttribute(ctx, path.Root("value_wo"), &valueWO)
	resp.Diagnostics.Append(diags...)

	newSecret, err := r.buildSecretPayload(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Secret Payload", fmt.Sprintf("Could not build secret payload: %s", err))
		return
	}
	if !data.Value.IsNull() {
		j := `{"rw": true}`
		diags := resp.Private.SetKey(ctx, "value_rw", []byte(j))
		resp.Diagnostics.Append(diags...)
	}
	if !valueWO.IsNull() {
		newSecret.Value = valueWO.ValueString()
	}

	err = r.checkPerms(data.Permissions)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Permissions error: %s", err))
		return
	}

	perms, err := r.buildPermissions(newSecret.Name, data.Permissions)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error building Permissions policy %s", err))
		return
	}
	permsYml, err := yaml.Marshal(perms)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error marshalling Permissions policy %s", err))
		return
	}

	secretResp, err := r.client.CreateStaticSecret(newSecret)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create secret, got error: %s", err))
		return
	}
	// TODO: Would be better to keep a map of policy mutexes, indexed by branch
	policyMutex.Lock()
	_, err = r.client.LoadPolicy(conjurapi.PolicyModePost, strings.TrimLeft(newSecret.Branch, "/"), bytes.NewReader(permsYml))
	policyMutex.Unlock()
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to set permissions: %s, %s", string(permsYml), err))
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
	for k, v := range secretResp.Annotations {
		if v == "" {
			delete(secretResp.Annotations, k)
		}
	}
	if len(secretResp.Annotations) > 0 {
		data.Annotations = secretResp.Annotations
	} else {
		data.Annotations = nil
	}

	// TODO: Computing this in Read when permissions have been applied via a different resource, i.e. conjur_permissions or in
	// Secrets Manager directly causes there be a diff on permissions even if they are unchanged, resulting in unnecessary updates.
	permissionResp, err := r.client.GetStaticSecretPermissions(secretID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading Secrets Manager secret permissions",
			fmt.Sprintf("Unable to check if secret %q permissions exist: %s", secretID, err),
		)
		return
	}
	perms := []ConjurSecretPermission{}
	for _, p := range permissionResp.Permission {
		kind := p.Subject.Kind
		// because obviously.
		if kind == "workload" {
			kind = "host"
		}
		sub := ConjurSecretSubject{
			Id:   types.StringValue(p.Subject.Id),
			Kind: types.StringValue(kind),
		}
		privs := []attr.Value{}
		for _, v := range p.Privileges {
			privs = append(privs, types.StringValue(v))
		}
		pvs, diags := types.SetValue(types.StringType, privs)
		resp.Diagnostics.Append(diags...)
		perms = append(perms, ConjurSecretPermission{
			Subject:    sub,
			Privileges: pvs,
		})
	}
	data.Permissions = perms

	err = r.parseSecretResponse(*secretResp, conjurapi.PermissionResponse{}, &data)
	if err != nil {
		resp.Diagnostics.AddError("Error Parsing Secret Response", fmt.Sprintf("Could not parse secret response: %s", err))
		return
	}

	b, diags := req.Private.GetKey(ctx, "value_rw")
	resp.Diagnostics.Append(diags...)
	// Fetch the secret value (if accessible) to store in state
	secretValue, err := r.client.RetrieveSecret(strings.TrimPrefix(secretID, "/"))
	if err != nil {
		resp.Diagnostics.AddWarning("Unable to fetch secret value", fmt.Sprintf("Could not fetch secret value for %q: %s", secretID, err))
	} else if len(b) > 0 && string(b) == `{"rw": true}` { // Only set the secret if "value" is configured, so that we don't populate the state if we're using value_wo (or if we're not managing the value with tf at all)
		if string(secretValue) != "" {
			resp.Diagnostics.AddWarning(
				"Sensitive Value in Configuration",
				"The 'value' attribute is marked as sensitive and will be stored in the Terraform state. Ensure your state file is securely managed.",
			)
		}
		data.Value = types.StringValue(string(secretValue))
	}

	tflog.Trace(ctx, "read secret resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Only supports rotating the secret value
func (r *ConjurSecretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var state, data ConjurSecretResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var valueWO types.String
	diags := req.Config.GetAttribute(ctx, path.Root("value_wo"), &valueWO)
	resp.Diagnostics.Append(diags...)

	secretID := fmt.Sprintf("%s/%s", data.Branch.ValueString(), data.Name.ValueString())

	perms, err := r.buildPermissions(data.Name.ValueString(), data.Permissions)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error building Permissions policy %s", err))
		return
	}

	err = r.checkPerms(data.Permissions)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Permissions error: %s", err))
		return
	}

	added, err := diffRemovedGrouped(data.Permissions, state.Permissions)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error building Permissions policy %s", err))
		return
	}
	removed, err := diffRemovedGrouped(state.Permissions, data.Permissions)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error building Permissions policy %s", err))
		return
	}
	denys := []policy.Deny{}
	for k, v := range removed {
		d := policy.Deny{
			Resource:   policy.Variable(data.Name.ValueString()),
			Role:       policy.Role{k.Kind.ValueString(), k.Id.ValueString()},
			Privileges: v,
		}
		denys = append(denys, d)
	}

	permsYml, err := yaml.Marshal(perms)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error marshalling Permissions policy %s", err))
		return
	}
	if len(denys) > 0 {
		denysYml, err := yaml.Marshal(denys)
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error marshalling Permissions policy %s", err))
			return
		}
		permsYml = append(permsYml, denysYml...)
	}

	for k, _ := range state.Annotations {
		// Can't unset the annotation unless we own the policy branch, which we have no guarantee of
		// Set the value to "" as the safest thing.
		if _, exists := data.Annotations[k]; !exists {
			if data.Annotations == nil {
				data.Annotations = map[string]string{}
			}
			data.Annotations[k] = ""
		}
	}
	if state.MimeType != data.MimeType {
		if data.Annotations == nil {
			data.Annotations = map[string]string{}
		}
		data.Annotations["conjur/mime_type"] = data.MimeType.ValueString()
	}

	annPol := policy.Annotations{
		VariableID:  data.Name.ValueString(),
		Annotations: data.Annotations,
	}
	annYml, err := yaml.Marshal([]policy.Annotations{annPol})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error marshalling Annotations policy %s", err))
		return
	}
	// Update the secret value
	if !valueWO.IsNull() {
		diags := resp.Private.SetKey(ctx, "value_rw", []byte{})
		resp.Diagnostics.Append(diags...)
		err = r.client.AddSecret(strings.TrimPrefix(secretID, "/"), valueWO.ValueString())
	} else if !data.Value.IsNull() {
		j := `{"rw": true}`
		diags := resp.Private.SetKey(ctx, "value_rw", []byte(j))
		resp.Diagnostics.Append(diags...)
		err = r.client.AddSecret(strings.TrimPrefix(secretID, "/"), data.Value.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddWarning("Unable to set secret value", fmt.Sprintf("Could not update secret value for %q: %s", secretID, err))
	} else {
		resp.Diagnostics.AddWarning(
			"Sensitive Value in Configuration",
			"The 'value' attribute is marked as sensitive and will be stored in the Terraform state. Ensure your state file is securely managed.",
		)
	}
	if len(added) > 0 || len(removed) > 0 {
		policyMutex.Lock()
		_, err = r.client.LoadPolicy(conjurapi.PolicyModePatch, strings.TrimLeft(data.Branch.ValueString(), "/"), bytes.NewReader(permsYml))
		policyMutex.Unlock()
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to set permissions: %s, %s", string(permsYml), err))
			return
		}
	}
	if !reflect.DeepEqual(state.Annotations, data.Annotations) {
		policyMutex.Lock()
		_, err = r.client.LoadPolicy(conjurapi.PolicyModePatch, strings.TrimLeft(data.Branch.ValueString(), "/"), bytes.NewReader(annYml))
		policyMutex.Unlock()
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to set annotations: %s, %s", string(annYml), err))
			return
		}
	}
	for k, v := range data.Annotations {
		if v == "" {
			delete(data.Annotations, k)
		}
	}
	delete(data.Annotations, "conjur/mime_type")
	if len(data.Annotations) == 0 {
		data.Annotations = nil
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

	err = policy.ApplyPolicy(r.client, deletionPolicy, strings.TrimPrefix(data.Branch.ValueString(), "/"))
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

func (r *ConjurSecretResource) buildPermissions(name string, perms []ConjurSecretPermission) ([]policy.Permit, error) {
	permits := []policy.Permit{}
	for _, v := range perms {
		privs := []string{}
		for _, vv := range v.Privileges.Elements() {
			privs = append(privs, vv.(types.String).ValueString())
		}
		p := policy.Permit{
			Resource:   policy.Variable(name),
			Role:       policy.Role{v.Subject.Kind.ValueString(), v.Subject.Id.ValueString()},
			Privileges: privs,
		}
		permits = append(permits, p)
	}

	return permits, nil
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
	/*
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
	*/
	if !data.Owner.IsNull() && !data.Owner.IsUnknown() {
		owner := &conjurapi.Owner{}
		if kindAttr, ok := data.Owner.Attributes()["kind"]; ok {
			owner.Kind = kindAttr.(types.String).ValueString()
		}
		if idAttr, ok := data.Owner.Attributes()["id"]; ok {
			owner.Id = idAttr.(types.String).ValueString()
		}
		secret.Owner = owner
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
				permission.Privileges = types.SetValueMust(types.StringType, privileges)
			} else {
				permission.Privileges = types.SetNull(types.StringType)
			}
			permissions[i] = permission
		}
		data.Permissions = permissions
	}

	if secretResp.Owner != nil {
		ownerAttrs := map[string]attr.Value{
			"kind": types.StringValue(secretResp.Owner.Kind),
			"id":   types.StringValue(secretResp.Owner.Id),
		}
		data.Owner = types.ObjectValueMust(map[string]attr.Type{
			"kind": types.StringType,
			"id":   types.StringType,
		}, ownerAttrs)
	} else {
		data.Owner = types.ObjectNull(map[string]attr.Type{
			"kind": types.StringType,
			"id":   types.StringType,
		})
	}

	if len(secretResp.Annotations) != 0 {
		data.Annotations = secretResp.Annotations
	}

	return nil
}

func (r *ConjurSecretResource) generateSecretDeletionPolicy(data *ConjurSecretResourceModel) (string, error) {
	delete := conjurpolicy.Delete{
		Record: conjurpolicy.ResourceRef{
			Kind: conjurpolicy.KindVariable,
			Id:   data.Name.ValueString(),
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

type RemovedPermissions map[ConjurSecretSubject][]string

func diffRemovedGrouped(state []ConjurSecretPermission, plan []ConjurSecretPermission) (RemovedPermissions, error) {

	stateMap, err := permissionsToMap(state)
	if err != nil {
		return nil, err
	}

	planMap, err := permissionsToMap(plan)
	if err != nil {
		return nil, err
	}

	removed := RemovedPermissions{}

	// Look for privileges that existed in state but not in plan
	for subjKey, statePrivs := range stateMap {
		planPrivs := planMap[subjKey]

		kind, id := parseSubjectKey(subjKey)
		subject := ConjurSecretSubject{
			Kind: types.StringValue(kind),
			Id:   types.StringValue(id),
		}

		for priv, _ := range statePrivs {
			if _, exists := planPrivs[priv]; !exists { // removed
				removed[subject] = append(removed[subject], priv)
			}
		}
	}

	return removed, nil
}

func subjectKey(s ConjurSecretSubject) string {
	return fmt.Sprintf("%s|%s", s.Kind.ValueString(), s.Id.ValueString())
}

func parseSubjectKey(s string) (string, string) {
	parts := strings.SplitN(s, "|", 2)
	return parts[0], parts[1]
}

func permissionsToMap(perms []ConjurSecretPermission) (map[string]map[string]bool, error) {
	out := make(map[string]map[string]bool)

	for _, p := range perms {
		key := subjectKey(p.Subject)

		privs := []string{}
		for _, vv := range p.Privileges.Elements() {
			privs = append(privs, vv.(types.String).ValueString())
		}

		if _, ok := out[key]; !ok {
			out[key] = make(map[string]bool)
		}

		for _, pr := range privs {
			out[key][pr] = true
		}
	}

	return out, nil
}

type WhoAmIResponse struct {
	Username string `json:"username"`
}

func (r *ConjurSecretResource) checkPerms(perms []ConjurSecretPermission) error {
	x, err := r.client.WhoAmI()
	if err != nil {
		return fmt.Errorf("Couldn't retrieve current user %s", err)
	}
	var wr WhoAmIResponse
	err = json.Unmarshal(x, &wr)
	if err != nil {
		return fmt.Errorf("Couldn't retrieve current user %s", err)
	}
	kind, user, found := strings.Cut(wr.Username, "/")
	if !found {
		return errors.New("Invalid user from WhoAmI")
	}
	hasRead := false
	for _, v := range perms {
		if v.Subject.Kind.ValueString() == kind && v.Subject.Id.ValueString() == user {
			privs := map[string]bool{}
			for _, vv := range v.Privileges.Elements() {
				privs[vv.(types.String).ValueString()] = true
			}
			if _, ok := privs["read"]; ok {
				hasRead = true
			}
		}
	}
	if !hasRead {
		return errors.New("Terraform user must be granted at least read access")
	}

	return nil
}
