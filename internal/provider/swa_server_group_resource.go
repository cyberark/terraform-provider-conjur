package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
)

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
	ID              types.String          `tfsdk:"id"`
	Name            types.String          `tfsdk:"name"`
	Description     types.String          `tfsdk:"description"`
	TrustDomainName types.String          `tfsdk:"trust_domain_name"`
	NodeAttestation *NodeAttestationModel `tfsdk:"node_attestation"`
}

type NodeAttestationModel struct {
	X509Pop *X509PopModel `tfsdk:"x509pop"`
	K8sPsat *K8sPsatModel `tfsdk:"k8s_psat"`
}

type X509PopModel struct {
	CaCertificates types.String `tfsdk:"ca_certificates"`
}

type K8sPsatModel struct {
	Clusters map[string]K8sPsatClusterModel `tfsdk:"clusters"`
}

type K8sPsatClusterModel struct {
	ServiceAccountAllowList types.List `tfsdk:"service_account_allow_list"`
	Audience                types.List `tfsdk:"audience"`
	AllowedPodLabelKeys     types.List `tfsdk:"allowed_pod_label_keys"`
	AllowedNodeLabelKeys    types.List `tfsdk:"allowed_node_label_keys"`
}

func NewServerGroupResource() resource.Resource {
	return &ServerGroupResource{}
}

// updateNodeAttestationFromResponse updates the model's NodeAttestation from the API response.
func updateNodeAttestationFromResponse(ctx context.Context, model *ServerGroupResourceModel, na *struct {
	K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
	X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
}) diag.Diagnostics {
	var diags diag.Diagnostics
	if na == nil {
		return diags
	}

	if model.NodeAttestation == nil {
		model.NodeAttestation = &NodeAttestationModel{}
	}

	if na.X509pop != nil {
		if model.NodeAttestation.X509Pop == nil {
			model.NodeAttestation.X509Pop = &X509PopModel{}
		}
		model.NodeAttestation.X509Pop.CaCertificates = types.StringValue(na.X509pop.CaCertificates)
	}

	if na.K8sPsat != nil && na.K8sPsat.Clusters != nil {
		if model.NodeAttestation.K8sPsat == nil {
			model.NodeAttestation.K8sPsat = &K8sPsatModel{}
		}
		if model.NodeAttestation.K8sPsat.Clusters == nil {
			model.NodeAttestation.K8sPsat.Clusters = make(map[string]K8sPsatClusterModel)
		}
		for clusterName, clusterConfig := range *na.K8sPsat.Clusters {
			cluster := K8sPsatClusterModel{}

			appendOptionalStringList(ctx, clusterConfig.ServiceAccountAllowList, &cluster.ServiceAccountAllowList, &diags)
			appendOptionalStringList(ctx, clusterConfig.Audience, &cluster.Audience, &diags)
			appendOptionalStringList(ctx, clusterConfig.AllowedPodLabelKeys, &cluster.AllowedPodLabelKeys, &diags)
			appendOptionalStringList(ctx, clusterConfig.AllowedNodeLabelKeys, &cluster.AllowedNodeLabelKeys, &diags)

			model.NodeAttestation.K8sPsat.Clusters[clusterName] = cluster
		}
	}
	return diags
}

// buildK8sPsatClusters converts the Terraform model to the API client cluster map.
func buildK8sPsatClusters(ctx context.Context, k8sPsat *K8sPsatModel) (map[string]swaclient.K8sPsatCluster, diag.Diagnostics) {
	var diags diag.Diagnostics
	if k8sPsat == nil || k8sPsat.Clusters == nil {
		return nil, diags
	}

	clusters := make(map[string]swaclient.K8sPsatCluster)
	for clusterName, clusterConfig := range k8sPsat.Clusters {
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

// buildNodeAttestationParts resolves the x509pop and k8s_psat parts from the model,
// ready to be assigned to a CreateServerGroupRequest or UpdateServerGroupRequest.
func buildNodeAttestationParts(ctx context.Context, na *NodeAttestationModel) (
	x509pop *swaclient.X509PopConfigurationInput,
	k8sPsat *swaclient.K8sPsatConfigurationInput,
	diags diag.Diagnostics,
) {
	if na == nil {
		return nil, nil, nil
	}
	if na.X509Pop != nil {
		x509pop = &swaclient.X509PopConfigurationInput{
			CaCertificates: na.X509Pop.CaCertificates.ValueString(),
		}
	}
	clusters, clusterDiags := buildK8sPsatClusters(ctx, na.K8sPsat)
	diags.Append(clusterDiags...)
	if clusters != nil {
		k8sPsat = &swaclient.K8sPsatConfigurationInput{Clusters: &clusters}
	}
	return x509pop, k8sPsat, diags
}

func hasAtLeastOneNodeAttestationMethod(na *NodeAttestationModel) bool {
	return na != nil && (na.X509Pop != nil || na.K8sPsat != nil)
}

func (r *ServerGroupResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_server_group"
}

func (r *ServerGroupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an SWA Server Group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the server group.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the server group.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "A description of the server group.",
				Optional:    true,
			},
			"trust_domain_name": schema.StringAttribute{
				Description: "The name of the trust domain this server group belongs to.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"node_attestation": schema.SingleNestedAttribute{
				Description: "Node attestation configuration. At least one of x509pop or k8s_psat must be specified.",
				Required:    true,
				Attributes: map[string]schema.Attribute{
					"x509pop": schema.SingleNestedAttribute{
						Description: "X.509 Proof of Possession attestation configuration.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"ca_certificates": schema.StringAttribute{
								Description: "PEM-encoded CA certificates for X.509 POP node attestation.",
								Required:    true,
							},
						},
					},
					"k8s_psat": schema.SingleNestedAttribute{
						Description: "Kubernetes Projected Service Account Token attestation configuration.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"clusters": schema.MapNestedAttribute{
								Description: "Map of cluster names to cluster configurations.",
								Required:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"service_account_allow_list": schema.ListAttribute{
											Description: "List of allowed service accounts in namespace/name format.",
											Optional:    true,
											ElementType: types.StringType,
										},
										"audience": schema.ListAttribute{
											Description: "Expected audience values for the PSAT token.",
											Optional:    true,
											ElementType: types.StringType,
										},
										"allowed_pod_label_keys": schema.ListAttribute{
											Description: "Pod label keys to include in attestation.",
											Optional:    true,
											ElementType: types.StringType,
										},
										"allowed_node_label_keys": schema.ListAttribute{
											Description: "Node label keys to include in attestation.",
											Optional:    true,
											ElementType: types.StringType,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *ServerGroupResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data ServerGroupResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() || data.NodeAttestation == nil {
		return
	}

	if !hasAtLeastOneNodeAttestationMethod(data.NodeAttestation) {
		resp.Diagnostics.AddError(
			"Invalid node_attestation",
			"At least one of x509pop or k8s_psat must be specified in node_attestation.",
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

	if !hasAtLeastOneNodeAttestationMethod(plan.NodeAttestation) {
		resp.Diagnostics.AddError(
			"Missing node attestation",
			"At least one of x509pop or k8s_psat must be specified in node_attestation.",
		)
		return
	}

	x509pop, k8sPsat, naDiags := buildNodeAttestationParts(ctx, plan.NodeAttestation)
	resp.Diagnostics.Append(naDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := swaclient.PostServerGroupJSONRequestBody{
		Name: plan.Name.ValueString(),
		NodeAttestation: struct {
			K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
			X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
		}{K8sPsat: k8sPsat, X509pop: x509pop},
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
	resp.Diagnostics.Append(updateNodeAttestationFromResponse(ctx, &plan, sgResp.NodeAttestation)...)

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
		resp.Diagnostics.Append(updateNodeAttestationFromResponse(ctx, &state, result.ApplicationxSecretsmgrV2JSON200.NodeAttestation)...)
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

	if !hasAtLeastOneNodeAttestationMethod(plan.NodeAttestation) {
		resp.Diagnostics.AddError(
			"Missing node attestation",
			"At least one of x509pop or k8s_psat must be specified in node_attestation.",
		)
		return
	}

	x509pop, k8sPsat, naDiags := buildNodeAttestationParts(ctx, plan.NodeAttestation)
	resp.Diagnostics.Append(naDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	updateReq.NodeAttestation = &struct {
		K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
		X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
	}{K8sPsat: k8sPsat, X509pop: x509pop}

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
		resp.Diagnostics.Append(updateNodeAttestationFromResponse(ctx, &plan, result.ApplicationxSecretsmgrV2JSON200.NodeAttestation)...)
	}

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
	}
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
