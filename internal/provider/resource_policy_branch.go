package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = &ConjurPolicyBranchResource{}
var _ resource.ResourceWithConfigure = &ConjurPolicyBranchResource{}
var _ resource.ResourceWithImportState = &ConjurPolicyBranchResource{}
var _ resource.ResourceWithValidateConfig = &ConjurPolicyBranchResource{}

func NewConjurPolicyBranchResource() resource.Resource {
	return &ConjurPolicyBranchResource{}
}

type ConjurPolicyBranchResource struct {
	client api.ClientV2
}

type ConjurPolicyBranchResourceModel struct {
	Name        types.String `tfsdk:"name"`
	Branch      types.String `tfsdk:"branch"`
	Owner       types.Object `tfsdk:"owner"`
	Annotations types.Map    `tfsdk:"annotations"`
	FullID      types.String `tfsdk:"full_id"`
}

func (r *ConjurPolicyBranchResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_branch"
}

func (r *ConjurPolicyBranchResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "CyberArk Secrets Manager Policy Branch resource",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Policy branch name (leaf)",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"branch": schema.StringAttribute{
				MarkdownDescription: "Parent policy path",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"owner": schema.SingleNestedAttribute{
				MarkdownDescription: "Owner of the policy branch",
				Optional:            true,
				Computed:            true,
				Attributes: map[string]schema.Attribute{
					"kind": schema.StringAttribute{
						MarkdownDescription: "Owner kind (user, group, etc.)",
						Computed:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"id": schema.StringAttribute{
						MarkdownDescription: "Owner identifier",
						Computed:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
				},
			},
			"annotations": schema.MapAttribute{
				MarkdownDescription: "Key-value annotations for the policy branch",
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.RequiresReplace(),
				},
			},
			"full_id": schema.StringAttribute{
				MarkdownDescription: "Computed identifier: `<branch>/<name>`",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *ConjurPolicyBranchResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data ConjurPolicyBranchResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ValidateNonEmpty(data.Name, &resp.Diagnostics, "Policy branch name")
	ValidateBranch(data.Branch, &resp.Diagnostics, "branch")
}

func (r *ConjurPolicyBranchResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ConjurPolicyBranchResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConjurPolicyBranchResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parent := strings.Trim(data.Branch.ValueString(), "/")
	leaf := strings.Trim(data.Name.ValueString(), "/")
	fullID := joinPath(parent, leaf)

	tflog.Debug(ctx, fmt.Sprintf("Creating policy branch: parent=%q, leaf=%q", parent, leaf))

	payload := conjurapi.Branch{
		Branch: parent,
		Name:   leaf,
	}

	if !data.Owner.IsNull() && !data.Owner.IsUnknown() {
		payload.Owner = &conjurapi.Owner{
			Kind: data.Owner.Attributes()["kind"].(types.String).ValueString(),
			Id:   data.Owner.Attributes()["id"].(types.String).ValueString(),
		}
	}

	if !data.Annotations.IsNull() && !data.Annotations.IsUnknown() {
		var anns map[string]string
		resp.Diagnostics.Append(data.Annotations.ElementsAs(ctx, &anns, false)...)
		if len(anns) > 0 {
			payload.Annotations = anns
		}
	}

	created, err := r.client.CreateBranch(payload)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("CreateBranch failed: %s", err))
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create policy branch: %s", err))
		return
	}

	data.Name = types.StringValue(created.Name)
	data.Branch = types.StringValue(parent)
	data.FullID = types.StringValue(fullID)
	data.Owner = ownerToObject(created.Owner)

	if created.Annotations != nil {
		mv, diags := types.MapValueFrom(ctx, types.StringType, created.Annotations)
		resp.Diagnostics.Append(diags...)
		data.Annotations = mv
	} else {
		data.Annotations = types.MapNull(types.StringType)
	}

	tflog.Trace(ctx, "Created policy branch resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurPolicyBranchResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConjurPolicyBranchResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parent := strings.Trim(data.Branch.ValueString(), "/")
	leaf := strings.Trim(data.Name.ValueString(), "/")
	fullID := joinPath(parent, leaf)

	tflog.Debug(ctx, fmt.Sprintf("Reading branch: parent=%q, leaf=%q, fullID=%q", parent, leaf, fullID))

	br, err := r.client.ReadBranch(fullID)
	if isNotFoundErr(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read policy branch %q: %s", fullID, err))
		return
	}

	data.Name = types.StringValue(br.Name)
	data.Branch = types.StringValue(parent)
	data.FullID = types.StringValue(fullID)

	data.Owner = ownerToObject(br.Owner)

	if br.Annotations != nil {
		mv, diags := types.MapValueFrom(ctx, types.StringType, br.Annotations)
		resp.Diagnostics.Append(diags...)
		data.Annotations = mv
	} else {
		data.Annotations = types.MapNull(types.StringType)
	}

	tflog.Trace(ctx, "Read policy branch resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Not supported in CC - requires resource recreation via planmodifiers since there's no PATCH support in the API
func (r *ConjurPolicyBranchResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddWarning(
		"Update will delete child resources!",
		"Recreating a policy branch will remove all resources under that branch path. Applying this change may therefore delete variables, hosts, or other resources under the branch.",
	)
}

func (r *ConjurPolicyBranchResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConjurPolicyBranchResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parent := strings.Trim(data.Branch.ValueString(), "/")
	leaf := strings.Trim(data.Name.ValueString(), "/")
	fullID := joinPath(parent, leaf)

	tflog.Debug(ctx, fmt.Sprintf("Deleting branch: parent=%q, leaf=%q, fullID=%q", parent, leaf, fullID))

	if _, err := r.client.DeleteBranch(fullID); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete policy branch %q: %s", fullID, err))
	}

	tflog.Trace(ctx, "Deleted policy branch resource")
	resp.State.RemoveResource(ctx)
}

func (r *ConjurPolicyBranchResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.Trim(req.ID, "/")
	if id == "" || !strings.Contains(id, "/") {
		resp.Diagnostics.AddError("Unexpected Import Identifier", "Expected format: <parent-branch>/<name>, e.g. apps/my-app/backend")
		return
	}

	parent, name := splitParentAndName(id)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("branch"), parent)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("full_id"), id)...)
}
func joinPath(parent, leaf string) string {
	parent = strings.Trim(parent, "/")
	leaf = strings.Trim(leaf, "/")
	if parent == "" {
		return leaf
	}
	return parent + "/" + leaf
}

func splitParentAndName(id string) (string, string) {
	id = strings.Trim(id, "/")
	idx := strings.LastIndex(id, "/")
	if idx < 0 {
		return "", id
	}
	return id[:idx], id[idx+1:]
}

func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") || strings.Contains(msg, "not found")
}

func ownerToObject(owner *conjurapi.Owner) types.Object {
	if owner == nil {
		return types.ObjectNull(map[string]attr.Type{
			"kind": types.StringType,
			"id":   types.StringType,
		})
	}
	obj, _ := types.ObjectValue(
		map[string]attr.Type{
			"kind": types.StringType,
			"id":   types.StringType,
		},
		map[string]attr.Value{
			"kind": types.StringValue(owner.Kind),
			"id":   types.StringValue(owner.Id),
		},
	)
	return obj
}
