package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
)

// nodeGroupNamePattern mirrors the API's NodeGroupName path parameter constraint:
// 1-60 characters, letters, numbers, periods, underscores, and hyphens only.
var nodeGroupNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &NodeGroupResource{}
	_ resource.ResourceWithConfigure   = &NodeGroupResource{}
	_ resource.ResourceWithImportState = &NodeGroupResource{}
)

type NodeGroupResource struct {
	client swaclient.ClientWithResponsesInterface
}

type NodeGroupResourceModel struct {
	ID                    types.String `tfsdk:"id"`
	Name                  types.String `tfsdk:"name"`
	Description           types.String `tfsdk:"description"`
	TrustDomainName       types.String `tfsdk:"trust_domain_name"`
	ServerGroupName       types.String `tfsdk:"server_group_name"`
	WorkloadType          types.String `tfsdk:"workload_type"`
	WorkloadConfiguration types.Object `tfsdk:"workload_configuration"`
}

type WorkloadConfigurationModel struct {
	SpiffeIDTemplate             types.String `tfsdk:"spiffe_id_template"`
	WorkloadRegistrationPolicies types.List   `tfsdk:"workload_registration_policies"`
}

// workloadConfigurationAttrTypes describes the object type of the
// workload_configuration nested attribute. It is used to build/parse
// types.Object values so that null/unknown/known states are represented
// correctly (a plain Go struct cannot represent "unknown").
var workloadConfigurationAttrTypes = map[string]attr.Type{
	"spiffe_id_template":             types.StringType,
	"workload_registration_policies": types.ListType{ElemType: types.StringType},
}

func NewNodeGroupResource() resource.Resource {
	return &NodeGroupResource{}
}

// buildWorkloadConfiguration converts the Terraform model to the API client WorkloadConfiguration.
// An unknown or null object is treated as "not configured" (nil), which means the
// request will omit workload_configuration entirely and let the server decide.
func buildWorkloadConfiguration(ctx context.Context, wcObj types.Object) (*swaclient.WorkloadConfiguration, diag.Diagnostics) {
	var diags diag.Diagnostics
	wc := modelFromObject[WorkloadConfigurationModel](ctx, wcObj, &diags)
	if wc == nil || diags.HasError() {
		return nil, diags
	}

	result := &swaclient.WorkloadConfiguration{}
	if !wc.SpiffeIDTemplate.IsNull() {
		t := wc.SpiffeIDTemplate.ValueString()
		result.SpiffeIdTemplate = &t
	}
	if !wc.WorkloadRegistrationPolicies.IsNull() {
		var policies []string
		diags.Append(wc.WorkloadRegistrationPolicies.ElementsAs(ctx, &policies, false)...)
		result.WorkloadRegistrationPolicies = &policies
	}
	return result, diags
}

func (r *NodeGroupResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_swa_node_group"
}

func (r *NodeGroupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an SWA Node Group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the node group.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the node group. Must be 1-60 characters and may include letters, numbers, periods, underscores, and hyphens only.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 60),
					stringvalidator.RegexMatches(nodeGroupNamePattern, "must contain only letters, numbers, periods, underscores, and hyphens"),
				},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the node group.",
				Optional:            true,
			},
			"trust_domain_name": schema.StringAttribute{
				MarkdownDescription: "The name of the trust domain.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"server_group_name": schema.StringAttribute{
				MarkdownDescription: "The name of the server group.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"workload_type": schema.StringAttribute{
				MarkdownDescription: "Type of workload for this node group. Valid values: 'unix', 'kubernetes'.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("unix", "kubernetes"),
				},
			},
			"workload_configuration": schema.SingleNestedAttribute{
				MarkdownDescription: "Workload configuration for the node group.",
				Optional:            true,
				Computed:            true,
				// Intentionally no UseStateForUnknown plan modifier: this attribute
				// must be able to transition from a known object back to null when a
				// user removes the block from their configuration (to reset defaults).
				// UseStateForUnknown would instead carry the prior known value forward,
				// making an explicit "clear" indistinguishable from "never configured".
				Attributes: map[string]schema.Attribute{
					"spiffe_id_template": schema.StringAttribute{
						MarkdownDescription: "SPIFFE ID template for workload identification. Uses Go template syntax.",
						Optional:            true,
					},
					"workload_registration_policies": schema.ListAttribute{
						MarkdownDescription: "List of CEL expressions for workload registration policies.",
						Optional:            true,
						ElementType:         types.StringType,
					},
				},
			},
		},
	}
}

func (r *NodeGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, ok := configureSWAClient(req, resp)
	if !ok {
		return
	}
	r.client = client
}

func (r *NodeGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var plan NodeGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := swaclient.PostNodeGroupsJSONRequestBody{
		Name:         plan.Name.ValueString(),
		WorkloadType: swaclient.NodeGroupCreateRequestWorkloadType(plan.WorkloadType.ValueString()),
	}
	if !plan.Description.IsNull() {
		createReq.Description = new(plan.Description.ValueString())
	}

	wc, wcDiags := buildWorkloadConfiguration(ctx, plan.WorkloadConfiguration)
	resp.Diagnostics.Append(wcDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if wc != nil {
		createReq.WorkloadConfiguration = wc
	}

	params := &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}
	result, err := r.client.PostNodeGroupsWithResponse(ctx, plan.TrustDomainName.ValueString(), plan.ServerGroupName.ValueString(), params, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating node group", err.Error())
		return
	}
	if !doSWARequest("creating node group", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusCreated) {
		return
	}

	if !requireSWAResponseBody("creating node group", result.ApplicationxSecretsmgrV2JSON201, &resp.Diagnostics) {
		return
	}
	ngResp := result.ApplicationxSecretsmgrV2JSON201

	plan.ID = types.StringValue(fmt.Sprintf("%s/%s/%s", plan.TrustDomainName.ValueString(), plan.ServerGroupName.ValueString(), ngResp.Name))
	plan.Name = types.StringValue(ngResp.Name)
	plan.WorkloadType = types.StringValue(string(ngResp.WorkloadType))
	plan.Description = optionalStringValue(ngResp.Description)
	// Keep state aligned with API response; workload_configuration is required in NodeGroupResponse.
	resp.Diagnostics.Append(syncWorkloadConfigFromResponse(ctx, &plan, &ngResp.WorkloadConfiguration)...)

	tflog.Trace(ctx, "created node group resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *NodeGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var state NodeGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}
	result, err := r.client.GetNodeGroupWithResponse(ctx, state.TrustDomainName.ValueString(), state.ServerGroupName.ValueString(), state.Name.ValueString(), params)
	if err != nil {
		resp.Diagnostics.AddError("Error reading node group", err.Error())
		return
	}
	if result.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}
	if !doSWARequest("reading node group", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusOK) {
		return
	}

	if !requireSWAResponseBody("reading node group", result.ApplicationxSecretsmgrV2JSON200, &resp.Diagnostics) {
		return
	}

	ngResp := result.ApplicationxSecretsmgrV2JSON200
	state.ID = types.StringValue(fmt.Sprintf("%s/%s/%s", state.TrustDomainName.ValueString(), state.ServerGroupName.ValueString(), ngResp.Name))
	state.Name = types.StringValue(ngResp.Name)
	state.WorkloadType = types.StringValue(string(ngResp.WorkloadType))
	state.Description = optionalStringValue(ngResp.Description)
	// Keep state aligned with API response; workload_configuration is required in NodeGroupResponse.
	resp.Diagnostics.Append(syncWorkloadConfigFromResponse(ctx, &state, &ngResp.WorkloadConfiguration)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *NodeGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var plan NodeGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateReq := swaclient.PatchNodeGroupJSONRequestBody{}
	if !plan.Description.IsNull() {
		updateReq.Description = new(plan.Description.ValueString())
	}

	wc, wcDiags := buildWorkloadConfiguration(ctx, plan.WorkloadConfiguration)
	resp.Diagnostics.Append(wcDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if wc != nil {
		updateReq.WorkloadConfiguration = wc
	} else {
		// When workload_configuration is removed from config, send an empty object to
		// signal a reset to server defaults. Only do this if it was previously set in
		// state so we don't send unnecessary payloads on unrelated updates.
		var state NodeGroupResourceModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if !state.WorkloadConfiguration.IsNull() {
			updateReq.WorkloadConfiguration = &swaclient.WorkloadConfiguration{}
		}
	}

	params := &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}
	result, err := r.client.PatchNodeGroupWithResponse(ctx, plan.TrustDomainName.ValueString(), plan.ServerGroupName.ValueString(), plan.Name.ValueString(), params, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating node group", err.Error())
		return
	}
	if !doSWARequest("updating node group", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusOK) {
		return
	}

	if !requireSWAResponseBody("updating node group", result.ApplicationxSecretsmgrV2JSON200, &resp.Diagnostics) {
		return
	}
	ngResp := result.ApplicationxSecretsmgrV2JSON200
	plan.Description = optionalStringValue(ngResp.Description)
	// Keep state aligned with API response; workload_configuration is required in NodeGroupResponse.
	resp.Diagnostics.Append(syncWorkloadConfigFromResponse(ctx, &plan, &ngResp.WorkloadConfiguration)...)

	tflog.Trace(ctx, "updated node group resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *NodeGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var state NodeGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := &swaclient.DeleteNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}
	result, err := r.client.DeleteNodeGroupWithResponse(ctx, state.TrustDomainName.ValueString(), state.ServerGroupName.ValueString(), state.Name.ValueString(), params)
	if err != nil {
		resp.Diagnostics.AddError("Error deleting node group", err.Error())
		return
	}
	if !doSWARequest("deleting node group", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusNoContent, http.StatusNotFound) {
		return
	}

	tflog.Trace(ctx, "deleted node group resource")
}

func (r *NodeGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts, err := splitSWAID(req.ID, 3, "trust_domain_name/server_group_name/node_group_name")
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("trust_domain_name"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("server_group_name"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[2])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// syncWorkloadConfigFromResponse updates model.WorkloadConfiguration from the API response.
// NodeGroupResponse requires workload_configuration, but the API returns an
// all-nil object when nothing is configured server-side. In that case we
// represent it as a null object so Terraform state correctly shows the
// workload_configuration block as absent, rather than present-but-empty.
func syncWorkloadConfigFromResponse(ctx context.Context, model *NodeGroupResourceModel, wc *swaclient.WorkloadConfiguration) diag.Diagnostics {
	var diags diag.Diagnostics
	if wc == nil || (wc.SpiffeIdTemplate == nil && wc.WorkloadRegistrationPolicies == nil) {
		model.WorkloadConfiguration = types.ObjectNull(workloadConfigurationAttrTypes)
		return diags
	}

	wcModel := WorkloadConfigurationModel{}
	if wc.SpiffeIdTemplate != nil {
		wcModel.SpiffeIDTemplate = types.StringValue(*wc.SpiffeIdTemplate)
	} else {
		wcModel.SpiffeIDTemplate = types.StringNull()
	}
	appendOptionalStringList(ctx, wc.WorkloadRegistrationPolicies, &wcModel.WorkloadRegistrationPolicies, &diags)

	obj, objDiags := types.ObjectValueFrom(ctx, workloadConfigurationAttrTypes, wcModel)
	diags.Append(objDiags...)
	model.WorkloadConfiguration = obj

	return diags
}
