package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
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
	typeName string
	client   swaclient.ClientWithResponsesInterface
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
	AwsIid            *AwsIidModel            `tfsdk:"aws_iid"`
	K8sJwt            *K8sJwtModel            `tfsdk:"k8s_jwt"`
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

type AwsIidModel struct {
	AssumeRole         types.String          `tfsdk:"assume_role"`
	Partition          types.String          `tfsdk:"partition"`
	VerifyOrganization *AwsIidVerifyOrgModel `tfsdk:"verify_organization"`
}

type AwsIidVerifyOrgModel struct {
	ManagementAccountID     types.String `tfsdk:"management_account_id"`
	ManagementAccountRegion types.String `tfsdk:"management_account_region"`
	AssumeOrgRole           types.String `tfsdk:"assume_org_role"`
	OrgAccountMapTTL        types.String `tfsdk:"org_account_map_ttl"`
	AccountListFile         types.String `tfsdk:"account_list_file"`
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

type K8sJwtModel struct {
	Clusters types.Map `tfsdk:"clusters"`
}

// K8sJwtClusterModel's PublicKeys reuses the JSON-string idiom established by
// ServerAuthenticationModel.PublicKeys (resource_swa_server.go) for the same
// `{"type":"jwks","value":<JWKS>}` shape, rather than modeling it as nested
// attributes, so both places that accept this shape look the same in HCL.
type K8sJwtClusterModel struct {
	Issuer                  types.String `tfsdk:"issuer"`
	Audience                types.String `tfsdk:"audience"`
	ServiceAccountAllowList types.List   `tfsdk:"service_account_allow_list"`
	JwksUri                 types.String `tfsdk:"jwks_uri"`
	PublicKeys              types.String `tfsdk:"public_keys"`
}

func k8sJwtClusterAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"issuer":                     types.StringType,
		"audience":                   types.StringType,
		"service_account_allow_list": types.ListType{ElemType: types.StringType},
		"jwks_uri":                   types.StringType,
		"public_keys":                types.StringType,
	}
}

func NewServerGroupResource() resource.Resource {
	return &ServerGroupResource{typeName: "conjur_swa_server_group"}
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
					Validators: []validator.String{
						stringvalidator.LengthAtLeast(1),
					},
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
								MarkdownDescription: "List of allowed service accounts in `namespace:name` format.",
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
					Computed:            true,
					ElementType:         types.StringType,
					// The API applies this same default server-side when the field is
					// omitted. Without Computed+Default here, the plan sees the config's
					// null value as final, and the value the API actually returns on
					// create/update looks like an inconsistent result to Terraform core.
					Default: listdefault.StaticValue(
						types.ListValueMust(types.StringType, []attr.Value{types.StringValue("urn:panw:swa")}),
					),
					Validators: []validator.List{
						listvalidator.SizeAtLeast(1),
					},
				},
			},
		},
		"aws_iid": schema.SingleNestedAttribute{
			MarkdownDescription: "AWS Instance Identity Document (IID) attestation configuration.",
			Optional:            true,
			Attributes: map[string]schema.Attribute{
				"assume_role": schema.StringAttribute{
					MarkdownDescription: "Bare IAM role name, optionally path-prefixed (e.g. `service-role/SWAServerRole`), to describe the attesting instance — not a full ARN. Used to build the full ARN per-attestation as `arn:{partition}:iam::{account-id}:role/{assume_role}`, taking the account ID from the attesting instance's Instance Identity Document. Omitted means ambient credentials (e.g. IRSA/Pod Identity) are used. Up to 576 characters; an empty string is treated the same as omitted.",
					Optional:            true,
					Validators: []validator.String{
						stringvalidator.LengthAtMost(576),
					},
				},
				"partition": schema.StringAttribute{
					MarkdownDescription: "AWS partition the server operates in. One of `aws`, `aws-cn`, `aws-us-gov`. Defaults to `aws`.",
					Optional:            true,
					Computed:            true,
					// The API applies this same default server-side when the field is
					// omitted. Without Computed+Default here, the plan sees the config's
					// null value as final, and the value the API actually returns on
					// create/update looks like an inconsistent result to Terraform core.
					Default: stringdefault.StaticString("aws"),
					Validators: []validator.String{
						stringvalidator.OneOf("aws", "aws-cn", "aws-us-gov"),
					},
				},
				"verify_organization": schema.SingleNestedAttribute{
					MarkdownDescription: "Verify the attesting instance belongs to an AWS Organization.",
					Optional:            true,
					Attributes: map[string]schema.Attribute{
						"management_account_id": schema.StringAttribute{
							MarkdownDescription: "12-digit AWS account ID of the organization's management (root) account.",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.RegexMatches(regexp.MustCompile(`^\d{12}$`), "must be a 12-digit AWS account ID"),
							},
						},
						"management_account_region": schema.StringAttribute{
							MarkdownDescription: "AWS region where the management account is hosted.",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
						},
						"assume_org_role": schema.StringAttribute{
							MarkdownDescription: "IAM role name in the management account with organizations:ListAccounts permissions.",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
						},
						"org_account_map_ttl": schema.StringAttribute{
							MarkdownDescription: "Cache TTL duration for the organization account list as a Go duration string (e.g. `15m`, `1h`, `90s`). Minimum duration is 1 minute (`1m`). Omitted means the attestor default is used.",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.RegexMatches(regexp.MustCompile(`^([0-9]+(h|m|s))+$`), "must be a Go duration string, e.g. '15m', '1h', '90s'"),
							},
						},
						"account_list_file": schema.StringAttribute{
							MarkdownDescription: "Path on the SWA server host/container to a file containing a JSON array of AWS account IDs. Mutually exclusive with `management_account_id` and `assume_org_role`.",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
						},
					},
				},
			},
		},
		"k8s_jwt": schema.SingleNestedAttribute{
			MarkdownDescription: "Kubernetes JWT attestation configuration.",
			Optional:            true,
			Attributes: map[string]schema.Attribute{
				"clusters": schema.MapNestedAttribute{
					MarkdownDescription: "Map of cluster identifier to Kubernetes JWT cluster configuration. Each key must match the name of an existing node group in this server group; that match is how an attesting workload's cluster is routed to a node group.",
					Required:            true,
					Validators: []validator.Map{
						mapvalidator.SizeAtLeast(1),
					},
					NestedObject: schema.NestedAttributeObject{
						Attributes: map[string]schema.Attribute{
							"issuer": schema.StringAttribute{
								MarkdownDescription: "OIDC issuer URL of the cluster, as it appears in the `iss` claim of its projected service account tokens. Up to 255 characters.",
								Required:            true,
								Validators: []validator.String{
									stringvalidator.LengthBetween(1, 255),
								},
							},
							"audience": schema.StringAttribute{
								MarkdownDescription: "Expected audience (`aud` claim) for projected service account tokens from this cluster. Up to 1000 characters.",
								Required:            true,
								Validators: []validator.String{
									stringvalidator.LengthBetween(1, 1000),
								},
							},
							"service_account_allow_list": schema.ListAttribute{
								MarkdownDescription: "Non-empty allowlist of Kubernetes service accounts (`namespace:name`) permitted to attest.",
								Required:            true,
								ElementType:         types.StringType,
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
								},
							},
							"jwks_uri": schema.StringAttribute{
								MarkdownDescription: "Cluster's published JWKS endpoint. Required for clusters that rotate signing keys too frequently for static keys (e.g. EKS, GKE, AKS). Must use `https` and resolve to a public host; `http`, localhost, loopback, and private/link-local/multicast addresses are rejected. Up to 255 characters. Mutually exclusive with `public_keys`.",
								Optional:            true,
								Validators: []validator.String{
									stringvalidator.LengthAtMost(255),
								},
							},
							"public_keys": schema.StringAttribute{
								MarkdownDescription: `Inline JWKS as a JSON string, in the form {"type":"jwks","value":{"keys":[...]}}. Requires no outbound network access; typically used for OpenShift and self-managed clusters. Mutually exclusive with jwks_uri.`,
								Optional:            true,
								PlanModifiers: []planmodifier.String{
									jsonEquivalentPlanModifier{},
								},
							},
						},
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

	if awsIid := at.AwsIid; awsIid != nil {
		awsIidModel := &AwsIidModel{
			AssumeRole: optionalStringValue(awsIid.AssumeRole),
			Partition:  types.StringNull(),
		}
		if awsIid.Partition != nil {
			awsIidModel.Partition = types.StringValue(string(*awsIid.Partition))
		}
		if vo := awsIid.VerifyOrganization; vo != nil {
			awsIidModel.VerifyOrganization = &AwsIidVerifyOrgModel{
				ManagementAccountID:     optionalStringValue(vo.ManagementAccountId),
				ManagementAccountRegion: optionalStringValue(vo.ManagementAccountRegion),
				AssumeOrgRole:           optionalStringValue(vo.AssumeOrgRole),
				OrgAccountMapTTL:        optionalStringValue(vo.OrgAccountMapTtl),
				AccountListFile:         optionalStringValue(vo.AccountListFile),
			}
		}
		attestation.AwsIid = awsIidModel
	}

	if k8sJwt := at.K8sJwt; k8sJwt != nil {
		// Look up prior per-cluster public_keys JSON so preferPriorJSONString below can
		// keep the user's original formatting instead of a reformatted-but-equivalent value.
		priorClusters := map[string]K8sJwtClusterModel{}
		if model.Attestation != nil && model.Attestation.K8sJwt != nil &&
			!model.Attestation.K8sJwt.Clusters.IsNull() && !model.Attestation.K8sJwt.Clusters.IsUnknown() {
			diags.Append(model.Attestation.K8sJwt.Clusters.ElementsAs(ctx, &priorClusters, false)...)
		}

		clusterObjs := make(map[string]attr.Value, len(k8sJwt.Clusters))
		for clusterName, clusterConfig := range k8sJwt.Clusters {
			cluster := K8sJwtClusterModel{
				Issuer:   types.StringValue(clusterConfig.Issuer),
				Audience: types.StringValue(clusterConfig.Audience),
				JwksUri:  optionalStringValue(clusterConfig.JwksUri),
			}

			saList, saDiags := types.ListValueFrom(ctx, types.StringType, clusterConfig.ServiceAccountAllowList)
			diags.Append(saDiags...)
			cluster.ServiceAccountAllowList = saList

			cluster.PublicKeys = types.StringNull()
			if clusterConfig.PublicKeys != nil {
				raw, err := json.Marshal(clusterConfig.PublicKeys)
				if err != nil {
					diags.AddError("Error encoding k8s_jwt public_keys", err.Error())
				} else {
					incoming := types.StringValue(string(raw))
					if prior, ok := priorClusters[clusterName]; ok {
						incoming = preferPriorJSONString(prior.PublicKeys, incoming)
					}
					cluster.PublicKeys = incoming
				}
			}

			obj, objDiags := types.ObjectValueFrom(ctx, k8sJwtClusterAttrTypes(), cluster)
			diags.Append(objDiags...)
			clusterObjs[clusterName] = obj
		}
		clustersMap, mapDiags := types.MapValue(
			types.ObjectType{AttrTypes: k8sJwtClusterAttrTypes()},
			clusterObjs,
		)
		diags.Append(mapDiags...)
		attestation.K8sJwt = &K8sJwtModel{Clusters: clustersMap}
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

// buildK8sJwtClusters converts the Terraform model to the API client cluster map.
func buildK8sJwtClusters(ctx context.Context, k8sJwt *K8sJwtModel) (map[string]swaclient.K8sJwtCluster, diag.Diagnostics) {
	var diags diag.Diagnostics
	if k8sJwt == nil || k8sJwt.Clusters.IsNull() || k8sJwt.Clusters.IsUnknown() {
		return nil, diags
	}

	clusterModels := make(map[string]K8sJwtClusterModel)
	diags.Append(k8sJwt.Clusters.ElementsAs(ctx, &clusterModels, false)...)
	if diags.HasError() {
		return nil, diags
	}

	clusters := make(map[string]swaclient.K8sJwtCluster, len(clusterModels))
	for clusterName, clusterConfig := range clusterModels {
		cluster := swaclient.K8sJwtCluster{
			Issuer:   clusterConfig.Issuer.ValueString(),
			Audience: clusterConfig.Audience.ValueString(),
			JwksUri:  stringPointerFromValue(clusterConfig.JwksUri),
		}

		var saList []string
		diags.Append(clusterConfig.ServiceAccountAllowList.ElementsAs(ctx, &saList, false)...)
		cluster.ServiceAccountAllowList = saList

		if knownStringValue(clusterConfig.PublicKeys) {
			var pk swaclient.K8sJwtClusterPublicKeys
			if err := json.Unmarshal([]byte(clusterConfig.PublicKeys.ValueString()), &pk); err != nil {
				diags.AddError("Invalid k8s_jwt public_keys JSON", err.Error())
				continue
			}
			cluster.PublicKeys = &pk
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

// buildAwsIid resolves the aws_iid part from the model.
func buildAwsIid(awsIid *AwsIidModel) *swaclient.AwsIidAttestationConfiguration {
	if awsIid == nil {
		return nil
	}

	config := &swaclient.AwsIidAttestationConfiguration{
		AssumeRole: stringPointerFromValue(awsIid.AssumeRole),
	}
	if knownStringValue(awsIid.Partition) {
		partition := swaclient.AwsIidAttestationConfigurationPartition(awsIid.Partition.ValueString())
		config.Partition = &partition
	}
	if vo := awsIid.VerifyOrganization; vo != nil {
		config.VerifyOrganization = &swaclient.AwsIidVerifyOrganizationConfiguration{
			ManagementAccountId:     stringPointerFromValue(vo.ManagementAccountID),
			ManagementAccountRegion: stringPointerFromValue(vo.ManagementAccountRegion),
			AssumeOrgRole:           stringPointerFromValue(vo.AssumeOrgRole),
			OrgAccountMapTtl:        stringPointerFromValue(vo.OrgAccountMapTTL),
			AccountListFile:         stringPointerFromValue(vo.AccountListFile),
		}
	}
	return config
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

	attestation.AwsIid = buildAwsIid(at.AwsIid)

	k8sJwtClusters, k8sJwtDiags := buildK8sJwtClusters(ctx, at.K8sJwt)
	diags.Append(k8sJwtDiags...)
	if k8sJwtClusters != nil {
		attestation.K8sJwt = &swaclient.K8sJwtAttestationConfiguration{Clusters: k8sJwtClusters}
	}

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
				MarkdownDescription: "The name of the server group. Case-sensitive; must be 1-60 characters and may include letters, numbers, periods, underscores, and hyphens only.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 60),
					stringvalidator.RegexMatches(swaResourceNamePattern, "must contain only letters, numbers, periods, underscores, and hyphens"),
				},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the server group. Up to 1024 characters.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(1024),
				},
			},
			"trust_domain_name": schema.StringAttribute{
				MarkdownDescription: "The name of the trust domain this server group belongs to.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"attestation": schema.SingleNestedAttribute{
				MarkdownDescription: "Node attestation configuration. Optionally specify any of x509pop, k8s_psat, gcp_service_account, aws_iid, or k8s_jwt; omit entirely for a server group with no attestation.",
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
	var nodeAttestation types.Object
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("node_attestation"), &nodeAttestation)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !nodeAttestation.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("node_attestation"),
			"Unsupported Attribute: node_attestation",
			"The `node_attestation` attribute was used by the previous Terraform provider that "+
				"this one replaces. Update your configuration to use "+
				"`attestation` instead.",
		)
	}

	validateK8sJwtConfig(ctx, req, resp)
}

// validateK8sJwtConfig fetches attestation.k8s_jwt directly by path rather than by
// decoding the whole attestation object into *AttestationModel: a sibling attestation
// variant (e.g. gcp_service_account) can be Unknown here when its config expression
// depends on a not-yet-resolved value (a conditional over an unresolved
// variable/resource attribute, for example), and reflecting an Unknown value into
// anything but a `types` package type is a hard error. Fetching just this one
// sub-attribute keeps that irrelevant, possibly-Unknown sibling out of the decode
// entirely.
func validateK8sJwtConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var k8sJwtObj types.Object
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("attestation").AtName("k8s_jwt"), &k8sJwtObj)...)
	if resp.Diagnostics.HasError() {
		return
	}

	k8sJwt := modelFromObject[K8sJwtModel](ctx, k8sJwtObj, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	validateK8sJwtClusters(ctx, k8sJwt, &resp.Diagnostics)
}

// validateK8sJwtClusters enforces that each k8s_jwt cluster sets exactly one of
// jwks_uri or public_keys, mirroring validateCreateServerAuthConfig's equivalent check
// for the server auth resource. Values sourced from variables or other resources are
// unknown at ValidateConfig time; the check is skipped for a cluster whose relevant
// fields are unknown to avoid false positives, since Create/Update run the same
// request-building path once values are resolved and the API enforces this too.
func validateK8sJwtClusters(ctx context.Context, k8sJwt *K8sJwtModel, diags *diag.Diagnostics) {
	if k8sJwt == nil || k8sJwt.Clusters.IsNull() || k8sJwt.Clusters.IsUnknown() {
		return
	}

	clusterModels := make(map[string]K8sJwtClusterModel)
	if d := k8sJwt.Clusters.ElementsAs(ctx, &clusterModels, false); d.HasError() {
		return
	}

	clustersPath := path.Root("attestation").AtName("k8s_jwt").AtName("clusters")
	for clusterName, cluster := range clusterModels {
		hasJwksURI := nonEmptyKnownStringValue(cluster.JwksUri)
		hasPublicKeys := nonEmptyKnownStringValue(cluster.PublicKeys)
		jwksUnknown := cluster.JwksUri.IsUnknown()
		publicKeysUnknown := cluster.PublicKeys.IsUnknown()

		if !hasJwksURI && !hasPublicKeys && !jwksUnknown && !publicKeysUnknown {
			diags.AddAttributeError(
				clustersPath.AtMapKey(clusterName),
				"Invalid k8s_jwt cluster configuration",
				fmt.Sprintf("cluster %q: one of jwks_uri or public_keys must be set.", clusterName),
			)
			continue
		}

		if hasJwksURI && hasPublicKeys {
			diags.AddAttributeError(
				clustersPath.AtMapKey(clusterName),
				"Invalid k8s_jwt cluster configuration",
				fmt.Sprintf("cluster %q: only one of jwks_uri or public_keys may be set, not both.", clusterName),
			)
		}
	}
}

func (r *ServerGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, ok := configureSWAClient(req, resp, r.typeName)
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

	if !doSWARequest("creating server group", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusCreated) {
		return
	}

	if !requireSWAResponseBody("creating server group", result.ApplicationxSecretsmgrV2JSON201, &resp.Diagnostics) {
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

	if !doSWARequest("reading server group", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusOK) {
		return
	}

	if !requireSWAResponseBody("reading server group", result.ApplicationxSecretsmgrV2JSON200, &resp.Diagnostics) {
		return
	}

	state.ID = types.StringValue(fmt.Sprintf("%s/%s", state.TrustDomainName.ValueString(), result.ApplicationxSecretsmgrV2JSON200.Name))
	state.Name = types.StringValue(result.ApplicationxSecretsmgrV2JSON200.Name)
	state.Description = optionalStringValue(result.ApplicationxSecretsmgrV2JSON200.Description)
	resp.Diagnostics.Append(updateAttestationFromResponse(ctx, &state, result.ApplicationxSecretsmgrV2JSON200.Attestation)...)
	if resp.Diagnostics.HasError() {
		return
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

	if !doSWARequest("updating server group", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusOK) {
		return
	}

	if !requireSWAResponseBody("updating server group", result.ApplicationxSecretsmgrV2JSON200, &resp.Diagnostics) {
		return
	}

	plan.ID = types.StringValue(fmt.Sprintf("%s/%s", result.ApplicationxSecretsmgrV2JSON200.TrustDomainName, result.ApplicationxSecretsmgrV2JSON200.Name))
	plan.Name = types.StringValue(result.ApplicationxSecretsmgrV2JSON200.Name)
	plan.TrustDomainName = types.StringValue(result.ApplicationxSecretsmgrV2JSON200.TrustDomainName)
	plan.Description = optionalStringValue(result.ApplicationxSecretsmgrV2JSON200.Description)
	resp.Diagnostics.Append(updateAttestationFromResponse(ctx, &plan, result.ApplicationxSecretsmgrV2JSON200.Attestation)...)
	if resp.Diagnostics.HasError() {
		return
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

	if !doSWARequest("deleting server group", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusNoContent, http.StatusNotFound) {
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
