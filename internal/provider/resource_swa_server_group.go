package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
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

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                   = &ServerGroupResource{}
	_ resource.ResourceWithConfigure      = &ServerGroupResource{}
	_ resource.ResourceWithImportState    = &ServerGroupResource{}
	_ resource.ResourceWithValidateConfig = &ServerGroupResource{}
)

type ServerGroupResource struct {
	client swaclient.ClientWithResponsesInterface
}

type ServerGroupResourceModel struct {
	ID              types.String      `tfsdk:"id"`
	Name            types.String      `tfsdk:"name"`
	Description     types.String      `tfsdk:"description"`
	TrustDomainName types.String      `tfsdk:"trust_domain_name"`
	Attestation     *AttestationModel `tfsdk:"attestation"`
	// NodeAttestation is the old provider's name for Attestation. It was renamed to
	// `attestation` before this provider's initial release, so this field exists solely
	// so ValidateConfig can detect stale configs written against the old provider and
	// return an actionable error instead of Terraform core's generic
	// "unsupported argument" message.
	NodeAttestation *AttestationModel `tfsdk:"node_attestation"`
}

type AttestationModel struct {
	X509Pop           *X509PopModel           `tfsdk:"x509pop"`
	K8sPsat           *K8sPsatModel           `tfsdk:"k8s_psat"`
	GcpServiceAccount *GcpServiceAccountModel `tfsdk:"gcp_service_account"`
}

type X509PopModel struct {
	CaCertificates types.String `tfsdk:"ca_certificates"`
}

type K8sPsatModel struct {
	Clusters types.Map `tfsdk:"clusters"`
}

type GcpServiceAccountModel struct {
	AllowedProjectIDs types.List `tfsdk:"allowed_project_ids"`
	Audiences         types.List `tfsdk:"audiences"`
}

type K8sPsatClusterModel struct {
	ServiceAccountAllowList types.List `tfsdk:"service_account_allow_list"`
	Audience                types.List `tfsdk:"audience"`
	AllowedPodLabelKeys     types.List `tfsdk:"allowed_pod_label_keys"`
	AllowedNodeLabelKeys    types.List `tfsdk:"allowed_node_label_keys"`
}

func k8sPsatClusterAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"service_account_allow_list": types.ListType{ElemType: types.StringType},
		"audience":                   types.ListType{ElemType: types.StringType},
		"allowed_pod_label_keys":     types.ListType{ElemType: types.StringType},
		"allowed_node_label_keys":    types.ListType{ElemType: types.StringType},
	}
}

func NewServerGroupResource() resource.Resource {
	return &ServerGroupResource{}
}

// attestationNestedAttributes returns the nested attribute schema shared by both the
// current `attestation` attribute and the deprecated,
// `node_attestation` attribute (see ServerGroupResourceModel.NodeAttestation). Keeping
// them identical ensures configs written against the old attribute name still parse
// successfully at the Terraform-core level, so the provider can surface a helpful
// rename error via ValidateConfig instead of core's generic "unsupported argument".
func attestationNestedAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"x509pop": schema.SingleNestedAttribute{
			MarkdownDescription: "X.509 Proof of Possession attestation configuration.",
			Optional:            true,
			Attributes: map[string]schema.Attribute{
				"ca_certificates": schema.StringAttribute{
					MarkdownDescription: "PEM-encoded CA certificates for X.509 POP node attestation.",
					Required:            true,
					Sensitive:           true,
				},
			},
		},
		"k8s_psat": schema.SingleNestedAttribute{
			MarkdownDescription: "Kubernetes Projected Service Account Token attestation configuration.",
			Optional:            true,
			Attributes: map[string]schema.Attribute{
				"clusters": schema.MapNestedAttribute{
					MarkdownDescription: "Map of cluster names to cluster configurations.",
					Optional:            true,
					NestedObject: schema.NestedAttributeObject{
						Attributes: map[string]schema.Attribute{
							"service_account_allow_list": schema.ListAttribute{
								MarkdownDescription: "List of allowed service accounts in namespace/name format.",
								Optional:            true,
								ElementType:         types.StringType,
							},
							"audience": schema.ListAttribute{
								MarkdownDescription: "Expected audience values for the PSAT token.",
								Optional:            true,
								ElementType:         types.StringType,
							},
							"allowed_pod_label_keys": schema.ListAttribute{
								MarkdownDescription: "Pod label keys to include in attestation.",
								Optional:            true,
								ElementType:         types.StringType,
							},
							"allowed_node_label_keys": schema.ListAttribute{
								MarkdownDescription: "Node label keys to include in attestation.",
								Optional:            true,
								ElementType:         types.StringType,
							},
						},
					},
				},
			},
		},
		"gcp_service_account": schema.SingleNestedAttribute{
			MarkdownDescription: "GCP service account attestation configuration.",
			Optional:            true,
			Attributes: map[string]schema.Attribute{
				"allowed_project_ids": schema.ListAttribute{
					MarkdownDescription: "List of allowed GCP project IDs.",
					Required:            true,
					ElementType:         types.StringType,
					Validators: []validator.List{
						listvalidator.SizeAtLeast(1),
					},
				},
				"audiences": schema.ListAttribute{
					MarkdownDescription: "Expected audience values for the GCP identity token (`aud` claim). Defaults to `urn:panw:swa` when omitted.",
					Optional:            true,
					ElementType:         types.StringType,
					Validators: []validator.List{
						listvalidator.SizeAtLeast(1),
					},
				},
			},
		},
	}
}

// updateAttestationFromResponse replaces the model's Attestation with exactly what the
// API response describes. This is a full reconciliation rather than a merge: attestation
// methods or clusters that are no longer present in the response are removed from state, so
// that out-of-band or server-side changes are surfaced on the next Read instead of silently
// persisting stale values from a prior plan or state.
func updateAttestationFromResponse(ctx context.Context, model *ServerGroupResourceModel, at *swaclient.AttestationConfiguration) diag.Diagnostics {
	var diags diag.Diagnostics

	if at == nil {
		model.Attestation = nil
		return diags
	}
	x509pop, k8sPsat, gcp := at.X509pop, at.K8sPsat, at.GcpServiceAccount

	attestation := &AttestationModel{}

	if x509pop != nil {
		attestation.X509Pop = &X509PopModel{
			CaCertificates: types.StringValue(x509pop.CaCertificates),
		}
	}

	if k8sPsat != nil && k8sPsat.Clusters != nil {
		clusterObjs := make(map[string]attr.Value, len(*k8sPsat.Clusters))
		for clusterName, clusterConfig := range *k8sPsat.Clusters {
			cluster := K8sPsatClusterModel{}
			appendOptionalStringList(ctx, clusterConfig.ServiceAccountAllowList, &cluster.ServiceAccountAllowList, &diags)
			appendOptionalStringList(ctx, clusterConfig.Audience, &cluster.Audience, &diags)
			appendOptionalStringList(ctx, clusterConfig.AllowedPodLabelKeys, &cluster.AllowedPodLabelKeys, &diags)
			appendOptionalStringList(ctx, clusterConfig.AllowedNodeLabelKeys, &cluster.AllowedNodeLabelKeys, &diags)
			obj, objDiags := types.ObjectValueFrom(ctx, k8sPsatClusterAttrTypes(), cluster)
			diags.Append(objDiags...)
			clusterObjs[clusterName] = obj
		}
		clustersMap, mapDiags := types.MapValue(
			types.ObjectType{AttrTypes: k8sPsatClusterAttrTypes()},
			clusterObjs,
		)
		diags.Append(mapDiags...)
		attestation.K8sPsat = &K8sPsatModel{Clusters: clustersMap}
	}

	if gcp != nil {
		gcpModel := &GcpServiceAccountModel{}
		allowed := append([]string(nil), gcp.AllowedProjectIds...)
		appendOptionalStringList(ctx, &allowed, &gcpModel.AllowedProjectIDs, &diags)
		appendOptionalStringList(ctx, gcp.Audiences, &gcpModel.Audiences, &diags)
		attestation.GcpServiceAccount = gcpModel
	}

	model.Attestation = attestation
	return diags
}

// buildK8sPsatClusters converts the Terraform model to the API client cluster map.
func buildK8sPsatClusters(ctx context.Context, k8sPsat *K8sPsatModel) (map[string]swaclient.K8sPsatCluster, diag.Diagnostics) {
	var diags diag.Diagnostics
	if k8sPsat == nil || k8sPsat.Clusters.IsNull() || k8sPsat.Clusters.IsUnknown() {
		return nil, diags
	}

	clusterModels := make(map[string]K8sPsatClusterModel)
	diags.Append(k8sPsat.Clusters.ElementsAs(ctx, &clusterModels, false)...)
	if diags.HasError() {
		return nil, diags
	}

	clusters := make(map[string]swaclient.K8sPsatCluster, len(clusterModels))
	for clusterName, clusterConfig := range clusterModels {
		cluster := swaclient.K8sPsatCluster{}

		if !clusterConfig.ServiceAccountAllowList.IsNull() {
			var saList []string
			diags.Append(clusterConfig.ServiceAccountAllowList.ElementsAs(ctx, &saList, false)...)
			cluster.ServiceAccountAllowList = &saList
		}
		if !clusterConfig.Audience.IsNull() {
			var audList []string
			diags.Append(clusterConfig.Audience.ElementsAs(ctx, &audList, false)...)
			cluster.Audience = &audList
		}
		if !clusterConfig.AllowedPodLabelKeys.IsNull() {
			var podLabels []string
			diags.Append(clusterConfig.AllowedPodLabelKeys.ElementsAs(ctx, &podLabels, false)...)
			cluster.AllowedPodLabelKeys = &podLabels
		}
		if !clusterConfig.AllowedNodeLabelKeys.IsNull() {
			var nodeLabels []string
			diags.Append(clusterConfig.AllowedNodeLabelKeys.ElementsAs(ctx, &nodeLabels, false)...)
			cluster.AllowedNodeLabelKeys = &nodeLabels
		}

		clusters[clusterName] = cluster
	}
	return clusters, diags
}

// buildGcpServiceAccount resolves the gcp_service_account part from the model.
func buildGcpServiceAccount(ctx context.Context, gcp *GcpServiceAccountModel) (*swaclient.GcpServiceAccountAttestationConfiguration, diag.Diagnostics) {
	var diags diag.Diagnostics
	if gcp == nil {
		return nil, diags
	}

	config := &swaclient.GcpServiceAccountAttestationConfiguration{}
	if !gcp.AllowedProjectIDs.IsNull() && !gcp.AllowedProjectIDs.IsUnknown() {
		diags.Append(gcp.AllowedProjectIDs.ElementsAs(ctx, &config.AllowedProjectIds, false)...)
	}
	if !gcp.Audiences.IsNull() && !gcp.Audiences.IsUnknown() {
		var audiences []string
		diags.Append(gcp.Audiences.ElementsAs(ctx, &audiences, false)...)
		config.Audiences = &audiences
	}
	return config, diags
}

// buildAttestationRequest resolves the attestation model into the API request field.
func buildAttestationRequest(ctx context.Context, at *AttestationModel) (*swaclient.AttestationConfiguration, diag.Diagnostics) {
	var diags diag.Diagnostics
	if at == nil {
		return nil, diags
	}

	attestation := &swaclient.AttestationConfiguration{}

	if at.X509Pop != nil {
		attestation.X509pop = &swaclient.X509PopConfigurationInput{
			CaCertificates: at.X509Pop.CaCertificates.ValueString(),
		}
	}

	clusters, clusterDiags := buildK8sPsatClusters(ctx, at.K8sPsat)
	diags.Append(clusterDiags...)
	if clusters != nil {
		attestation.K8sPsat = &swaclient.K8sPsatConfigurationInput{Clusters: &clusters}
	}

	gcp, gcpDiags := buildGcpServiceAccount(ctx, at.GcpServiceAccount)
	diags.Append(gcpDiags...)
	attestation.GcpServiceAccount = gcp

	return attestation, diags
}

func (r *ServerGroupResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_swa_server_group"
}

func (r *ServerGroupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an SWA Server Group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the server group.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the server group.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the server group.",
				Optional:            true,
			},
			"trust_domain_name": schema.StringAttribute{
				MarkdownDescription: "The name of the trust domain this server group belongs to.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"attestation": schema.SingleNestedAttribute{
				MarkdownDescription: "Node attestation configuration. Optionally specify any of x509pop, k8s_psat, or gcp_service_account; omit entirely for a server group with no attestation.",
				Optional:            true,
				Attributes:          attestationNestedAttributes(),
			},
			// node_attestation was the attribute name used prior to this provider's
			// initial release; it was renamed to `attestation` before release and has
			// never been functional. It is kept in the schema
			// so that stale configs written against the old provider still pass
			// Terraform-core's config validation, allowing ValidateConfig below to
			// return a clear, actionable rename error instead of core's generic
			// "unsupported argument" message.
			"node_attestation": schema.SingleNestedAttribute{
				MarkdownDescription: "Deprecated: use `attestation` instead.",
				DeprecationMessage:  "node_attestation was used by the previous Terraform provider this one replaces. Update your configuration to use `attestation` instead.",
				Optional:            true,
				Attributes:          attestationNestedAttributes(),
			},
		},
	}
}



func (r *ServerGroupResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data ServerGroupResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.NodeAttestation != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("node_attestation"),
			"Unsupported Attribute: node_attestation",
			"The `node_attestation` attribute was used by the previous Terraform provider that "+
				"this one replaces. Update your configuration to use "+
				"`attestation` instead.",
		)
	}
}

func (r *ServerGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, ok := configureSWAClient(req, resp)
	if !ok {
		return
	}
	r.client = client
}

func (r *ServerGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var plan ServerGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	attestation, attDiags := buildAttestationRequest(ctx, plan.Attestation)
	resp.Diagnostics.Append(attDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := swaclient.PostServerGroupJSONRequestBody{
		Name:        plan.Name.ValueString(),
		Attestation: attestation,
	}

	if !plan.Description.IsNull() {
		createReq.Description = new(plan.Description.ValueString())
	}

	params := &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	result, err := r.client.PostServerGroupWithResponse(ctx, plan.TrustDomainName.ValueString(), params, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating server group", err.Error())
		return
	}

	if result.StatusCode() != http.StatusCreated {
		summary, detail := apiStatusError("creating server group", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON201 == nil {
		resp.Diagnostics.AddError("Error creating server group", "No response body")
		return
	}
	sgResp := result.ApplicationxSecretsmgrV2JSON201

	plan.ID = types.StringValue(fmt.Sprintf("%s/%s", sgResp.TrustDomainName, sgResp.Name))
	plan.Name = types.StringValue(sgResp.Name)
	plan.TrustDomainName = types.StringValue(sgResp.TrustDomainName)
	plan.Description = optionalStringValue(sgResp.Description)
	resp.Diagnostics.Append(updateAttestationFromResponse(ctx, &plan, sgResp.Attestation)...)

	tflog.Trace(ctx, "created server group resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *ServerGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var state ServerGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := &swaclient.GetServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	result, err := r.client.GetServerGroupWithResponse(ctx, state.TrustDomainName.ValueString(), state.Name.ValueString(), params)
	if err != nil {
		resp.Diagnostics.AddError("Error reading server group", err.Error())
		return
	}

	if result.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if result.StatusCode() != http.StatusOK {
		summary, detail := apiStatusError("reading server group", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON200 != nil {
		state.ID = types.StringValue(fmt.Sprintf("%s/%s", state.TrustDomainName.ValueString(), result.ApplicationxSecretsmgrV2JSON200.Name))
		state.Name = types.StringValue(result.ApplicationxSecretsmgrV2JSON200.Name)
		state.Description = optionalStringValue(result.ApplicationxSecretsmgrV2JSON200.Description)
		resp.Diagnostics.Append(updateAttestationFromResponse(ctx, &state, result.ApplicationxSecretsmgrV2JSON200.Attestation)...)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *ServerGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var plan ServerGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateReq := swaclient.PatchServerGroupJSONRequestBody{}

	if !plan.Description.IsNull() {
		updateReq.Description = new(plan.Description.ValueString())
	}

	attestation, attDiags := buildAttestationRequest(ctx, plan.Attestation)
	resp.Diagnostics.Append(attDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	updateReq.Attestation = attestation

	params := &swaclient.PatchServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	// name and trust_domain_name are RequiresReplace, so plan values equal state values.
	result, err := r.client.PatchServerGroupWithResponse(ctx, plan.TrustDomainName.ValueString(), plan.Name.ValueString(), params, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating server group", err.Error())
		return
	}

	if result.StatusCode() != http.StatusOK {
		summary, detail := apiStatusError("updating server group", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON200 != nil {
		plan.ID = types.StringValue(fmt.Sprintf("%s/%s", result.ApplicationxSecretsmgrV2JSON200.TrustDomainName, result.ApplicationxSecretsmgrV2JSON200.Name))
		plan.Name = types.StringValue(result.ApplicationxSecretsmgrV2JSON200.Name)
		plan.TrustDomainName = types.StringValue(result.ApplicationxSecretsmgrV2JSON200.TrustDomainName)
		plan.Description = optionalStringValue(result.ApplicationxSecretsmgrV2JSON200.Description)
		resp.Diagnostics.Append(updateAttestationFromResponse(ctx, &plan, result.ApplicationxSecretsmgrV2JSON200.Attestation)...)
	}

	tflog.Trace(ctx, "updated server group resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *ServerGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var state ServerGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := &swaclient.DeleteServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	result, err := r.client.DeleteServerGroupWithResponse(ctx, state.TrustDomainName.ValueString(), state.Name.ValueString(), params)
	if err != nil {
		resp.Diagnostics.AddError("Error deleting server group", err.Error())
		return
	}

	if result.StatusCode() != http.StatusNoContent && result.StatusCode() != http.StatusNotFound {
		summary, detail := apiStatusError("deleting server group", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	tflog.Trace(ctx, "deleted server group resource")
}

func (r *ServerGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts, err := splitSWAID(req.ID, 2, "trust_domain_name/server_group_name")
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("trust_domain_name"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[1])...)
}
