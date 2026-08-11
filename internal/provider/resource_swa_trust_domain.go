package provider

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
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
	_ resource.Resource                = &TrustDomainResource{}
	_ resource.ResourceWithConfigure   = &TrustDomainResource{}
	_ resource.ResourceWithImportState = &TrustDomainResource{}
)

// jwtAttrTypes and x509AttrTypes define the attribute type maps for the
// corresponding nested objects. types.Object requires these for construction
// and for As() deserialization.
var jwtAttrTypes = map[string]attr.Type{
	"signature_algorithm": types.StringType,
	"signing_key_type":    types.StringType,
	"signing_key_ttl":     types.Int64Type,
	"token_ttl":           types.Int64Type,
}

var x509AttrTypes = map[string]attr.Type{
	"workload_ttl": types.Int64Type,
}

type TrustDomainResource struct {
	typeName string
	client   swaclient.ClientWithResponsesInterface
}

// TrustDomainResourceModel uses types.Object for jwt and x509 so the framework
// can represent unknown values (which arise when Optional+Computed attributes
// are not specified by the user on first apply).
type TrustDomainResourceModel struct {
	ID   types.String `tfsdk:"id"`
	Name types.String `tfsdk:"name"`
	JWT  types.Object `tfsdk:"jwt"`  // attributes: JWTConfigModel
	X509 types.Object `tfsdk:"x509"` // attributes: X509ConfigModel
}

type JWTConfigModel struct {
	SignatureAlgorithm types.String `tfsdk:"signature_algorithm"`
	SigningKeyType     types.String `tfsdk:"signing_key_type"`
	SigningKeyTTL      types.Int64  `tfsdk:"signing_key_ttl"`
	TokenTTL           types.Int64  `tfsdk:"token_ttl"`
}

type X509ConfigModel struct {
	WorkloadTTL types.Int64 `tfsdk:"workload_ttl"`
}

func trustDomainJWTObject(ctx context.Context, jwt swaclient.JWTConfiguration) (types.Object, diag.Diagnostics) {
	return types.ObjectValueFrom(ctx, jwtAttrTypes, &JWTConfigModel{
		SignatureAlgorithm: types.StringValue(string(jwt.SignatureAlgorithm)),
		SigningKeyType:     types.StringValue(string(jwt.SigningKeyType)),
		SigningKeyTTL:      types.Int64Value(int64(jwt.SigningKeyTtl)),
		TokenTTL:           types.Int64Value(int64(jwt.TokenTtl)),
	})
}

func trustDomainX509Object(ctx context.Context, x509 swaclient.X509Configuration) (types.Object, diag.Diagnostics) {
	return types.ObjectValueFrom(ctx, x509AttrTypes, &X509ConfigModel{
		WorkloadTTL: types.Int64Value(int64(x509.WorkloadTtl)),
	})
}

func setTrustDomainStateFromResponse(ctx context.Context, model *TrustDomainResourceModel, td *swaclient.TrustDomainResponse) diag.Diagnostics {
	var diags diag.Diagnostics
	if td == nil {
		return diags
	}

	model.ID = types.StringValue(td.Name)
	model.Name = types.StringValue(td.Name)

	jwtObj, jwtDiags := trustDomainJWTObject(ctx, td.Jwt)
	diags.Append(jwtDiags...)
	if diags.HasError() {
		return diags
	}
	model.JWT = jwtObj

	x509Obj, x509Diags := trustDomainX509Object(ctx, td.X509)
	diags.Append(x509Diags...)
	if diags.HasError() {
		return diags
	}
	model.X509 = x509Obj

	return diags
}

func NewTrustDomainResource() resource.Resource {
	return &TrustDomainResource{typeName: "conjur_swa_trust_domain"}
}

func (r *TrustDomainResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_swa_trust_domain"
}

func (r *TrustDomainResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an SWA Trust Domain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the trust domain.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the trust domain (e.g., 'prod.example.org').",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"jwt": schema.SingleNestedAttribute{
				MarkdownDescription: "JWT SVID configuration for the trust domain.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"signature_algorithm": schema.StringAttribute{
						MarkdownDescription: "The signature algorithm for JWTs (e.g., 'ES256', 'RS256').",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("RS512"),
					},
					"signing_key_type": schema.StringAttribute{
						MarkdownDescription: "The type of signing key (e.g., 'EC_P256', 'RSA_2048').",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("RSA_4096"),
					},
					"signing_key_ttl": schema.Int64Attribute{
						MarkdownDescription: "TTL for signing keys in seconds.",
						Optional:            true,
						Computed:            true,
						Default:             int64default.StaticInt64(86400),
					},
					"token_ttl": schema.Int64Attribute{
						MarkdownDescription: "TTL for JWT tokens in seconds.",
						Optional:            true,
						Computed:            true,
						Default:             int64default.StaticInt64(300),
					},
				},
			},
			"x509": schema.SingleNestedAttribute{
				MarkdownDescription: "X.509 SVID configuration for the trust domain.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"workload_ttl": schema.Int64Attribute{
						MarkdownDescription: "TTL for workload X.509 SVIDs in seconds.",
						Optional:            true,
						Computed:            true,
						Default:             int64default.StaticInt64(3600),
						Validators: []validator.Int64{
							int64validator.Between(600, 86400),
						},
					},
				},
			},
		},
	}
}

func (r *TrustDomainResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, ok := configureSWAClient(req, resp, r.typeName)
	if !ok {
		return
	}
	r.client = client
}

func (r *TrustDomainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var plan TrustDomainResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := swaclient.PostTrustDomainJSONRequestBody{
		Name: plan.Name.ValueString(),
	}

	if !applyOptionalModel(ctx, plan.JWT, &resp.Diagnostics, func(jwtCfg *JWTConfigModel) {
		createReq.Jwt = &swaclient.JWTConfigurationInput{
			SignatureAlgorithm: new(swaclient.JWTConfigurationInputSignatureAlgorithm(jwtCfg.SignatureAlgorithm.ValueString())),
			SigningKeyType:     new(swaclient.JWTConfigurationInputSigningKeyType(jwtCfg.SigningKeyType.ValueString())),
			SigningKeyTtl:      new(int32(jwtCfg.SigningKeyTTL.ValueInt64())),
			TokenTtl:           new(int32(jwtCfg.TokenTTL.ValueInt64())),
		}
	}) {
		return
	}

	if !applyOptionalModel(ctx, plan.X509, &resp.Diagnostics, func(x509Cfg *X509ConfigModel) {
		createReq.X509 = &swaclient.X509ConfigurationInput{
			WorkloadTtl: new(int32(x509Cfg.WorkloadTTL.ValueInt64())),
		}
	}) {
		return
	}

	params := &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	result, err := r.client.PostTrustDomainWithResponse(ctx, params, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating trust domain", err.Error())
		return
	}

	if !doSWARequest("creating trust domain", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusCreated) {
		return
	}

	if !requireSWAResponseBody("creating trust domain", result.ApplicationxSecretsmgrV2JSON201, &resp.Diagnostics) {
		return
	}

	resp.Diagnostics.Append(setTrustDomainStateFromResponse(ctx, &plan, result.ApplicationxSecretsmgrV2JSON201)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "created trust domain resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *TrustDomainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var state TrustDomainResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := &swaclient.GetTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	result, err := r.client.GetTrustDomainWithResponse(ctx, state.Name.ValueString(), params)
	if err != nil {
		resp.Diagnostics.AddError("Error reading trust domain", err.Error())
		return
	}

	if result.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if !doSWARequest("reading trust domain", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusOK) {
		return
	}

	if !requireSWAResponseBody("reading trust domain", result.ApplicationxSecretsmgrV2JSON200, &resp.Diagnostics) {
		return
	}

	resp.Diagnostics.Append(setTrustDomainStateFromResponse(ctx, &state, result.ApplicationxSecretsmgrV2JSON200)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *TrustDomainResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var plan TrustDomainResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateReq := swaclient.PatchTrustDomainJSONRequestBody{}
	if plan.JWT.IsNull() && plan.X509.IsNull() {
		resp.Diagnostics.AddError(
			"Invalid trust domain update",
			"At least one of jwt or x509 must be set for update.",
		)
		return
	}

	if !applyOptionalModel(ctx, plan.JWT, &resp.Diagnostics, func(jwtCfg *JWTConfigModel) {
		updateReq.Jwt = &swaclient.UpdateJWTConfigurationInput{
			SignatureAlgorithm: new(swaclient.UpdateJWTConfigurationInputSignatureAlgorithm(jwtCfg.SignatureAlgorithm.ValueString())),
			SigningKeyType:     new(swaclient.UpdateJWTConfigurationInputSigningKeyType(jwtCfg.SigningKeyType.ValueString())),
			SigningKeyTtl:      new(int32(jwtCfg.SigningKeyTTL.ValueInt64())),
			TokenTtl:           new(int32(jwtCfg.TokenTTL.ValueInt64())),
		}
	}) {
		return
	}

	if !applyOptionalModel(ctx, plan.X509, &resp.Diagnostics, func(x509Cfg *X509ConfigModel) {
		updateReq.X509 = &swaclient.UpdateX509ConfigurationInput{
			WorkloadTtl: int32(x509Cfg.WorkloadTTL.ValueInt64()),
		}
	}) {
		return
	}

	params := &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	// name is RequiresReplace, so plan.Name equals state.Name.
	result, err := r.client.PatchTrustDomainWithResponse(ctx, plan.Name.ValueString(), params, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating trust domain", err.Error())
		return
	}

	if !doSWARequest("updating trust domain", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusOK) {
		return
	}

	if !requireSWAResponseBody("updating trust domain", result.ApplicationxSecretsmgrV2JSON200, &resp.Diagnostics) {
		return
	}

	resp.Diagnostics.Append(setTrustDomainStateFromResponse(ctx, &plan, result.ApplicationxSecretsmgrV2JSON200)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "updated trust domain resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *TrustDomainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var state TrustDomainResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := &swaclient.DeleteTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	result, err := r.client.DeleteTrustDomainWithResponse(ctx, state.Name.ValueString(), params)
	if err != nil {
		resp.Diagnostics.AddError("Error deleting trust domain", err.Error())
		return
	}

	if !doSWARequest("deleting trust domain", result.StatusCode(), result.Body, &resp.Diagnostics, http.StatusNoContent, http.StatusNotFound) {
		return
	}

	tflog.Trace(ctx, "deleted trust domain resource")
}

func (r *TrustDomainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}
