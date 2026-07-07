package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
	ID                    types.String                `tfsdk:"id"`
	Name                  types.String                `tfsdk:"name"`
	Description           types.String                `tfsdk:"description"`
	TrustDomainName       types.String                `tfsdk:"trust_domain_name"`
	ServerGroupName       types.String                `tfsdk:"server_group_name"`
	WorkloadType          types.String                `tfsdk:"workload_type"`
	WorkloadConfiguration *WorkloadConfigurationModel `tfsdk:"workload_configuration"`
}

type WorkloadConfigurationModel struct {
	SpiffeIDTemplate             types.String `tfsdk:"spiffe_id_template"`
	WorkloadRegistrationPolicies types.List   `tfsdk:"workload_registration_policies"`
}

func NewNodeGroupResource() resource.Resource {
	return &NodeGroupResource{}
}

// buildWorkloadConfiguration converts the Terraform model to the API client WorkloadConfiguration.
func buildWorkloadConfiguration(ctx context.Context, wc *WorkloadConfigurationModel) (*swaclient.WorkloadConfiguration, diag.Diagnostics) {
	if wc == nil {
		return nil, nil
	}

	var diags diag.Diagnostics
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
		MarkdownDescription:"Manages an SWA Node Group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription:"The unique identifier of the node group.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription:"The name of the node group. Must be 1-60 characters and may include letters, numbers, periods, underscores, and hyphens only.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 60),
					stringvalidator.RegexMatches(nodeGroupNamePattern, "must contain only letters, numbers, periods, underscores, and hyphens"),
				},
			},
			"description": schema.StringAttribute{
				MarkdownDescription:"A description of the node group.",
				Optional:    true,
			},
			"trust_domain_name": schema.StringAttribute{
				MarkdownDescription:"The name of the trust domain.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"server_group_name": schema.StringAttribute{
				MarkdownDescription:"The name of the server group.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"workload_type": schema.StringAttribute{
				MarkdownDescription:"Type of workload for this node group. Valid values: 'unix', 'kubernetes'.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("unix", "kubernetes"),
				},
			},
			"workload_configuration": schema.SingleNestedAttribute{
				MarkdownDescription:"Workload configuration for the node group.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"spiffe_id_template": schema.StringAttribute{
						MarkdownDescription:"SPIFFE ID template for workload identification. Uses Go template syntax.",
						Optional:    true,
					},
					"workload_registration_policies": schema.ListAttribute{
						MarkdownDescription:"List of CEL expressions for workload registration policies.",
						Optional:    true,
						ElementType: types.StringType,
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
	if result.StatusCode() != http.StatusCreated {
		summary, detail := apiStatusError("creating node group", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON201 == nil {
		resp.Diagnostics.AddError("Error creating node group", "No response body")
		return
	}
	ngResp := result.ApplicationxSecretsmgrV2JSON201

	plan.ID = types.StringValue(fmt.Sprintf("%s/%s/%s", plan.TrustDomainName.ValueString(), plan.ServerGroupName.ValueString(), ngResp.Name))
	plan.Name = types.StringValue(ngResp.Name)
	plan.WorkloadType = types.StringValue(string(ngResp.WorkloadType))
	plan.Description = optionalStringValue(ngResp.Description)
	// Always sync workload_configuration from the API response.
	// If no fields are set server-side the optional block stays absent (nil) in state.
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
	if result.StatusCode() != http.StatusOK {
		summary, detail := apiStatusError("reading node group", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON200 != nil {
		ngResp := result.ApplicationxSecretsmgrV2JSON200
		state.ID = types.StringValue(fmt.Sprintf("%s/%s/%s", state.TrustDomainName.ValueString(), state.ServerGroupName.ValueString(), ngResp.Name))
		state.Name = types.StringValue(ngResp.Name)
		state.WorkloadType = types.StringValue(string(ngResp.WorkloadType))
		state.Description = optionalStringValue(ngResp.Description)
		// Always sync workload_configuration from the API response.
		// If no fields are set server-side the optional block stays absent (nil) in state.
		resp.Diagnostics.Append(syncWorkloadConfigFromResponse(ctx, &state, &ngResp.WorkloadConfiguration)...)
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
		if state.WorkloadConfiguration != nil {
			updateReq.WorkloadConfiguration = &swaclient.WorkloadConfiguration{}
		}
	}

	params := &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}
	result, err := r.client.PatchNodeGroupWithResponse(ctx, plan.TrustDomainName.ValueString(), plan.ServerGroupName.ValueString(), plan.Name.ValueString(), params, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating node group", err.Error())
		return
	}
	if result.StatusCode() != http.StatusOK {
		summary, detail := apiStatusError("updating node group", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON200 == nil {
		resp.Diagnostics.AddError("Error updating node group", "No response body")
		return
	}
	ngResp := result.ApplicationxSecretsmgrV2JSON200
	plan.Description = optionalStringValue(ngResp.Description)
	// Always sync workload_configuration from the API response.
	// If no fields are set server-side the optional block stays absent (nil) in state.
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
	if result.StatusCode() != http.StatusNoContent && result.StatusCode() != http.StatusNotFound {
		summary, detail := apiStatusError("deleting node group", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
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
// If the server returned no workload configuration fields (all nil), the optional block is
// removed from state (set to nil) so users who omit the block in config see no diff.
func syncWorkloadConfigFromResponse(ctx context.Context, model *NodeGroupResourceModel, wc *swaclient.WorkloadConfiguration) diag.Diagnostics {
	if wc == nil || (wc.SpiffeIdTemplate == nil && wc.WorkloadRegistrationPolicies == nil) {
		// Server returned nothing — keep the optional block absent in state.
		model.WorkloadConfiguration = nil
		return nil
	}
	var diags diag.Diagnostics
	if model.WorkloadConfiguration == nil {
		model.WorkloadConfiguration = &WorkloadConfigurationModel{}
	}
	if wc.SpiffeIdTemplate != nil {
		model.WorkloadConfiguration.SpiffeIDTemplate = types.StringValue(*wc.SpiffeIdTemplate)
	} else {
		model.WorkloadConfiguration.SpiffeIDTemplate = types.StringNull()
	}
	appendOptionalStringList(ctx, wc.WorkloadRegistrationPolicies, &model.WorkloadConfiguration.WorkloadRegistrationPolicies, &diags)

	return diags
}
