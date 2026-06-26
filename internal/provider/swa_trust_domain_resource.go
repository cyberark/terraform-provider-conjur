package provider

import (
	"context"
	"net/http"

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
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
)

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
	client swaclient.ClientWithResponsesInterface
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

// jwtConfigFromObject deserializes a types.Object into a JWTConfigModel.
// Returns nil (without adding diagnostics) when the object is null or unknown.
func jwtConfigFromObject(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *JWTConfigModel {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var cfg JWTConfigModel
	diags.Append(obj.As(ctx, &cfg, basetypes.ObjectAsOptions{})...)
	return &cfg
}

// x509ConfigFromObject deserializes a types.Object into an X509ConfigModel.
// Returns nil (without adding diagnostics) when the object is null or unknown.
func x509ConfigFromObject(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *X509ConfigModel {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var cfg X509ConfigModel
	diags.Append(obj.As(ctx, &cfg, basetypes.ObjectAsOptions{})...)
	return &cfg
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
	return &TrustDomainResource{}
}

func (r *TrustDomainResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trust_domain"
}

func (r *TrustDomainResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an SWA Trust Domain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the trust domain.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the trust domain (e.g., 'prod.example.org').",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"jwt": schema.SingleNestedAttribute{
				Description: "JWT SVID configuration for the trust domain.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"signature_algorithm": schema.StringAttribute{
						Description: "The signature algorithm for JWTs (e.g., 'ES256', 'RS256').",
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("RS512"),
					},
					"signing_key_type": schema.StringAttribute{
						Description: "The type of signing key (e.g., 'EC_P256', 'RSA_2048').",
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("RSA_4096"),
					},
					"signing_key_ttl": schema.Int64Attribute{
						Description: "TTL for signing keys in seconds.",
						Optional:    true,
						Computed:    true,
						Default:     int64default.StaticInt64(86400),
					},
					"token_ttl": schema.Int64Attribute{
						Description: "TTL for JWT tokens in seconds.",
						Optional:    true,
						Computed:    true,
						Default:     int64default.StaticInt64(300),
					},
				},
			},
			"x509": schema.SingleNestedAttribute{
				Description: "X.509 SVID configuration for the trust domain.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"workload_ttl": schema.Int64Attribute{
						Description: "TTL for workload X.509 SVIDs in seconds.",
						Optional:    true,
						Computed:    true,
						Default:     int64default.StaticInt64(3600),
					},
				},
			},
		},
	}
}

func (r *TrustDomainResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, ok := configureSWAClient(req, resp)
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

	if jwtCfg := jwtConfigFromObject(ctx, plan.JWT, &resp.Diagnostics); jwtCfg != nil {
		if resp.Diagnostics.HasError() {
			return
		}
		createReq.Jwt = &swaclient.JWTConfigurationInput{
			SignatureAlgorithm: ptr(swaclient.JWTConfigurationInputSignatureAlgorithm(jwtCfg.SignatureAlgorithm.ValueString())),
			SigningKeyType:     ptr(swaclient.JWTConfigurationInputSigningKeyType(jwtCfg.SigningKeyType.ValueString())),
			SigningKeyTtl:      ptr(int32(jwtCfg.SigningKeyTTL.ValueInt64())),
			TokenTtl:           ptr(int32(jwtCfg.TokenTTL.ValueInt64())),
		}
	}

	if x509Cfg := x509ConfigFromObject(ctx, plan.X509, &resp.Diagnostics); x509Cfg != nil {
		if resp.Diagnostics.HasError() {
			return
		}
		createReq.X509 = &swaclient.X509ConfigurationInput{
			WorkloadTtl: ptr(int32(x509Cfg.WorkloadTTL.ValueInt64())),
		}
	}

	params := &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	result, err := r.client.PostTrustDomainWithResponse(ctx, params, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating trust domain", err.Error())
		return
	}

	if result.StatusCode() != http.StatusCreated {
		summary, detail := apiStatusError("creating trust domain", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON201 == nil {
		resp.Diagnostics.AddError("Error creating trust domain", "No response body")
		return
	}

	resp.Diagnostics.Append(setTrustDomainStateFromResponse(ctx, &plan, result.ApplicationxSecretsmgrV2JSON201)...)
	if resp.Diagnostics.HasError() {
		return
	}

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

	if result.StatusCode() != http.StatusOK {
		summary, detail := apiStatusError("reading trust domain", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON200 != nil {
		resp.Diagnostics.Append(setTrustDomainStateFromResponse(ctx, &state, result.ApplicationxSecretsmgrV2JSON200)...)
		if resp.Diagnostics.HasError() {
			return
		}
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

	if jwtCfg := jwtConfigFromObject(ctx, plan.JWT, &resp.Diagnostics); jwtCfg != nil {
		if resp.Diagnostics.HasError() {
			return
		}
		updateReq.Jwt = &swaclient.UpdateJWTConfigurationInput{
			SignatureAlgorithm: ptr(swaclient.UpdateJWTConfigurationInputSignatureAlgorithm(jwtCfg.SignatureAlgorithm.ValueString())),
			SigningKeyType:     ptr(swaclient.UpdateJWTConfigurationInputSigningKeyType(jwtCfg.SigningKeyType.ValueString())),
			SigningKeyTtl:      ptr(int32(jwtCfg.SigningKeyTTL.ValueInt64())),
			TokenTtl:           ptr(int32(jwtCfg.TokenTTL.ValueInt64())),
		}
	}

	if x509Cfg := x509ConfigFromObject(ctx, plan.X509, &resp.Diagnostics); x509Cfg != nil {
		if resp.Diagnostics.HasError() {
			return
		}
		updateReq.X509 = &swaclient.UpdateX509ConfigurationInput{
			WorkloadTtl: int32(x509Cfg.WorkloadTTL.ValueInt64()),
		}
	}

	params := &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	// name is RequiresReplace, so plan.Name equals state.Name.
	result, err := r.client.PatchTrustDomainWithResponse(ctx, plan.Name.ValueString(), params, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating trust domain", err.Error())
		return
	}

	if result.StatusCode() != http.StatusOK {
		summary, detail := apiStatusError("updating trust domain", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON200 != nil {
		resp.Diagnostics.Append(setTrustDomainStateFromResponse(ctx, &plan, result.ApplicationxSecretsmgrV2JSON200)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

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

	if result.StatusCode() != http.StatusNoContent && result.StatusCode() != http.StatusNotFound {
		summary, detail := apiStatusError("deleting trust domain", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
	}
}

func (r *TrustDomainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}
