package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/cyberark/terraform-provider-conjur/internal/policy"
	"github.com/doodlesbykumbi/conjur-policy-go/pkg/conjurpolicy"
	"gopkg.in/yaml.v3"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &ConjurPermissionResource{}
	_ resource.ResourceWithConfigure   = &ConjurPermissionResource{}
	_ resource.ResourceWithImportState = &ConjurPermissionResource{}
)

func NewConjurPermissionResource() resource.Resource {
	return &ConjurPermissionResource{}
}

// ConjurPermissionResource defines the resource implementation.
type ConjurPermissionResource struct {
	client *conjurapi.Client
}

// ConjurPermissionResourceModel describes the resource data model.
type ConjurPermissionResourceModel struct {
	Role       RoleModel     `tfsdk:"role"`
	Resource   ResourceModel `tfsdk:"resource"`
	Privileges types.List    `tfsdk:"privileges"`
}

// RoleModel represents the nested "role" block
type RoleModel struct {
	Name   types.String `tfsdk:"name"`
	Kind   types.String `tfsdk:"kind"`
	Branch types.String `tfsdk:"branch"`
}

// ResourceModel represents the nested "resource" block
type ResourceModel struct {
	Name   types.String `tfsdk:"name"`
	Kind   types.String `tfsdk:"kind"`
	Branch types.String `tfsdk:"branch"`
}

func (r *ConjurPermissionResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_permission"
}

func (r *ConjurPermissionResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Conjur permission resource",
		Attributes: map[string]schema.Attribute{
			"role": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Required: true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"kind": schema.StringAttribute{
						Required: true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"branch": schema.StringAttribute{
						Required: true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
				},
			},
			"resource": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Required: true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"kind": schema.StringAttribute{
						Required: true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"branch": schema.StringAttribute{
						Required: true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
				},
			},
			"privileges": schema.ListAttribute{
				MarkdownDescription: "List of privileges to grant on the resource",
				ElementType:         types.StringType,
				Required:            true,
			},
		},
	}
}

func (r *ConjurPermissionResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*conjurapi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *ConjurClient, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *ConjurPermissionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConjurPermissionResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	branch, permissionPolicy, err := r.generatePermissionPolicy(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Permission Policy", fmt.Sprintf("Could not build Permission policy: %s", err))
		return
	}

	// TODO - determine root branch manually since we can't assume "data" for on-prem users?
	err = policy.ApplyPolicy(r.client, permissionPolicy, branch)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to load Permission policy, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "created permission resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurPermissionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConjurPermissionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	// for each supported privilege, check if it exists and update the state accordingly
	// TODO: think about if this causes unexpected behavior for inherited privileges
	// also custom privileges?
	privs := []string{"read", "update", "execute", "create"}
	rolePrivs := make([]attr.Value, 0, len(privs))

	for _, priv := range privs {
		hasPriv, err := r.client.CheckPermissionForRole(
			fmt.Sprintf("%s:%s", data.Resource.Kind.ValueString(), joinConjurID(data.Resource.Branch.ValueString(), data.Resource.Name.ValueString())),
			fmt.Sprintf("%s:%s", data.Role.Kind.ValueString(), joinConjurID(data.Role.Branch.ValueString(), data.Role.Name.ValueString())),
			priv,
		)
		if err != nil {
			resp.Diagnostics.AddError("Client Error",
				fmt.Sprintf("Unable to check permission via API, got error: %s", err))
			return
		}
		if hasPriv {
			rolePrivs = append(rolePrivs, types.StringValue(priv))
		}
	}

	data.Privileges = types.ListValueMust(types.StringType, rolePrivs)

	tflog.Trace(ctx, "read permission resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurPermissionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ConjurPermissionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	branch, permissionPolicy, err := r.generatePermissionPolicy(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Permission Policy", fmt.Sprintf("Could not build Permission policy: %s", err))
		return
	}

	err = policy.ApplyPolicy(r.client, permissionPolicy, branch)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to load Permission policy, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "updated permission resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurPermissionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConjurPermissionResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	branch, permissionPolicy, err := r.generatePermissionDenyPolicy(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Permission Delete Policy", fmt.Sprintf("Could not build Permission Delete policy: %s", err))
		return
	}

	err = policy.ApplyPolicy(r.client, permissionPolicy, branch)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to load Permission policy, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "deleted permission resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurPermissionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			"Expected format: kind/branch/role:kind/branch/resource",
		)
		return
	}

	roleInput := parts[0]
	resourceInput := parts[1]

	roleKind, roleBranch, roleName, err := splitConjurID(roleInput)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Role Identifier",
			fmt.Sprintf("Error parsing role identifier: %s", err),
		)
		return
	}

	resourceKind, resourceBranch, resourceName, err := splitConjurID(resourceInput)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Resource Identifier",
			fmt.Sprintf("Error parsing resource identifier: %s", err),
		)
		return
	}

	roleBlock := types.ObjectValueMust(
		map[string]attr.Type{
			"name":   types.StringType,
			"kind":   types.StringType,
			"branch": types.StringType,
		},
		map[string]attr.Value{
			"name":   types.StringValue(roleName),
			"kind":   types.StringValue(roleKind),
			"branch": types.StringValue(roleBranch),
		},
	)

	resourceBlock := types.ObjectValueMust(
		map[string]attr.Type{
			"name":   types.StringType,
			"kind":   types.StringType,
			"branch": types.StringType,
		},
		map[string]attr.Value{
			"name":   types.StringValue(resourceName),
			"kind":   types.StringValue(resourceKind),
			"branch": types.StringValue(resourceBranch),
		},
	)

	// Set nested blocks in state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role"), roleBlock)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("resource"), resourceBlock)...)
}

// generatePermissionPolicy creates a policy that grants privileges explicitly added via the resource data, and denies all others
func (r *ConjurPermissionResource) generatePermissionPolicy(data *ConjurPermissionResourceModel) (string, string, error) {
	granted, notGranted, err := parsePrivileges(data)
	if err != nil {
		return "", "", err
	}

	roleKind, resKind, err := validateKinds(data)
	if err != nil {
		return "", "", err
	}

	branch, roleID, resourceID := derivePolicyContext(data)

	policy := conjurpolicy.PolicyStatements{
		conjurpolicy.Permit{
			Role:       conjurpolicy.ResourceRef{Kind: roleKind, Id: roleID},
			Resources:  conjurpolicy.ResourceRef{Kind: resKind, Id: resourceID},
			Privileges: granted,
		},
		conjurpolicy.Deny{
			Role:       conjurpolicy.ResourceRef{Kind: roleKind, Id: roleID},
			Resources:  conjurpolicy.ResourceRef{Kind: resKind, Id: resourceID},
			Privileges: notGranted,
		},
	}

	yamlBytes, err := yaml.Marshal(policy)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal policy: %w", err)
	}
	return branch, string(yamlBytes), nil
}

// generatePermissionDenyPolicy creates a policy that denies previously granted privileges
func (r *ConjurPermissionResource) generatePermissionDenyPolicy(data *ConjurPermissionResourceModel) (string, string, error) {
	granted, _, err := parsePrivileges(data)
	if err != nil {
		return "", "", err
	}

	roleKind, resKind, err := validateKinds(data)
	if err != nil {
		return "", "", err
	}

	branch, roleID, resourceID := derivePolicyContext(data)

	policy := conjurpolicy.PolicyStatements{
		conjurpolicy.Deny{
			Role:       conjurpolicy.ResourceRef{Kind: roleKind, Id: roleID},
			Resources:  conjurpolicy.ResourceRef{Kind: resKind, Id: resourceID},
			Privileges: granted,
		},
	}

	yamlBytes, err := yaml.Marshal(policy)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal policy: %w", err)
	}
	return branch, string(yamlBytes), nil
}

// parsePrivileges returns a list of granted and not-granted privileges
func parsePrivileges(data *ConjurPermissionResourceModel) ([]conjurpolicy.Privilege, []conjurpolicy.Privilege, error) {
	privilegeMap := map[string]conjurpolicy.Privilege{
		"read":    conjurpolicy.PrivilegeRead,
		"update":  conjurpolicy.PrivilegeUpdate,
		"execute": conjurpolicy.PrivilegeExecute,
		"create":  conjurpolicy.PrivilegeCreate,
	}

	// Determine granted privileges
	privList := []conjurpolicy.Privilege{}
	for _, priv := range data.Privileges.Elements() {
		key := priv.(types.String).ValueString()
		privObj, exists := privilegeMap[key]
		if !exists {
			return nil, nil, fmt.Errorf("invalid privilege: %s", key)
		}
		privList = append(privList, privObj)
	}

	// Determine non-granted privileges
	denyList := []conjurpolicy.Privilege{}
	for _, privObj := range privilegeMap {
		if !slices.Contains(privList, privObj) {
			denyList = append(denyList, privObj)
		}
	}

	return privList, denyList, nil
}

// validateKinds returns the resolved kinds for role and resource
func validateKinds(data *ConjurPermissionResourceModel) (conjurpolicy.Kind, conjurpolicy.Kind, error) {
	kindMap := map[string]conjurpolicy.Kind{
		"user":     conjurpolicy.KindUser,
		"group":    conjurpolicy.KindGroup,
		"host":     conjurpolicy.KindHost,
		"layer":    conjurpolicy.KindLayer,
		"variable": conjurpolicy.KindVariable,
		"policy":   conjurpolicy.KindPolicy,
	}

	roleKind, ok := kindMap[data.Role.Kind.ValueString()]
	if !ok {
		return 0, 0, fmt.Errorf("invalid role kind: %s", data.Role.Kind.ValueString())
	}
	resKind, ok := kindMap[data.Resource.Kind.ValueString()]
	if !ok {
		return 0, 0, fmt.Errorf("invalid resource kind: %s", data.Resource.Kind.ValueString())
	}
	return roleKind, resKind, nil
}

// derivePolicyContext calculates the lowest shared branch, plus relative role/resource IDs
func derivePolicyContext(data *ConjurPermissionResourceModel) (branch, roleID, resourceID string) {
	// Find common ancestor branch
	branch = mergePolicyBranch(data.Role.Branch.ValueString(), data.Resource.Branch.ValueString())

	// Build full IDs
	fullRoleID := joinConjurID(data.Role.Branch.ValueString(), data.Role.Name.ValueString())
	fullResourceID := joinConjurID(data.Resource.Branch.ValueString(), data.Resource.Name.ValueString())

	// Trim shared ancestor branch to make relative IDs
	roleID = strings.TrimPrefix(fullRoleID, branch+"/")
	resourceID = strings.TrimPrefix(fullResourceID, branch+"/")

	return branch, roleID, resourceID
}

// joinConjurID creates a full Conjur ID by joining branch (if it exists) and name
func joinConjurID(branch, name string) string {
	branch = strings.Trim(branch, "/")
	if branch == "" {
		return name
	}
	return branch + "/" + name
}

// mergePolicyBranch determines the lowest-level shared policy branch between two Conjur IDs for loading new policy
func mergePolicyBranch(a, b string) string {
	// Normalize and split the policy branches
	partsA := strings.Split(strings.Trim(a, "/"), "/")
	partsB := strings.Split(strings.Trim(b, "/"), "/")

	var shared []string
	for i := 0; i < len(partsA) && i < len(partsB); i++ {
		if partsA[i] != partsB[i] {
			break
		}
		shared = append(shared, partsA[i])
	}

	return strings.Join(shared, "/")
}

// splitConjurID splits a full Conjur ID into kind, branch, and name components
func splitConjurID(fullID string) (kind, branch, name string, err error) {
	segments := strings.Split(fullID, "/")
	if len(segments) < 2 {
		// At minimum we expect kind + name
		return "", "", "", fmt.Errorf("invalid Conjur ID: %s. Expected at least kind/name", fullID)
	}

	kind = segments[0]
	name = segments[len(segments)-1]
	if len(segments) > 2 {
		branch = strings.Join(segments[1:len(segments)-1], "/")
	} else {
		branch = ""
	}
	return kind, branch, name, nil
}
