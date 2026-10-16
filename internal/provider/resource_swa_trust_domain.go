package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework-validators/float64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/float64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
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
	_ resource.Resource                   = &TrustDomainResource{}
	_ resource.ResourceWithConfigure      = &TrustDomainResource{}
	_ resource.ResourceWithImportState    = &TrustDomainResource{}
	_ resource.ResourceWithValidateConfig = &TrustDomainResource{}
	_ resource.ResourceWithModifyPlan     = &TrustDomainResource{}
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

var x509CAConfigAttrTypes = map[string]attr.Type{
	"root_ca_ttl":                    types.Int64Type,
	"root_key_algorithm":             types.StringType,
	"root_rotation_trigger_fraction": types.Float64Type,
}

var x509CAAttrTypes = map[string]attr.Type{
	"type":   types.StringType,
	"config": types.ObjectType{AttrTypes: x509CAConfigAttrTypes},
}

var x509AttrTypes = map[string]attr.Type{
	"workload_ttl":                 types.Int64Type,
	"intermediate_certificate_ttl": types.Int64Type,
	"intermediate_key_algorithm":   types.StringType,
	"ca":                           types.ObjectType{AttrTypes: x509CAAttrTypes},
}

type TrustDomainResource struct {
	resourceBase[swaclient.ClientWithResponsesInterface]
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
	WorkloadTTL                types.Int64  `tfsdk:"workload_ttl"`
	IntermediateCertificateTTL types.Int64  `tfsdk:"intermediate_certificate_ttl"`
	IntermediateKeyAlgorithm   types.String `tfsdk:"intermediate_key_algorithm"`
	CA                         types.Object `tfsdk:"ca"` // attributes: X509CAModel
}

type X509CAModel struct {
	Type   types.String `tfsdk:"type"`
	Config types.Object `tfsdk:"config"` // attributes: X509CAConfigModel
}

type X509CAConfigModel struct {
	RootCATTL                   types.Int64   `tfsdk:"root_ca_ttl"`
	RootKeyAlgorithm            types.String  `tfsdk:"root_key_algorithm"`
	RootRotationTriggerFraction types.Float64 `tfsdk:"root_rotation_trigger_fraction"`
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
	var diags diag.Diagnostics

	// The API omits optional fields it has no value for; map those to null
	// rather than a zero value that would diverge from the configuration.
	caObj := types.ObjectNull(x509CAAttrTypes)
	if x509.Ca != nil {
		caObj, diags = trustDomainCAObject(ctx, x509.Ca)
		if diags.HasError() {
			return types.ObjectNull(x509AttrTypes), diags
		}
	}

	model := &X509ConfigModel{
		WorkloadTTL:                types.Int64Value(int64(x509.WorkloadTtl)),
		IntermediateCertificateTTL: types.Int64Null(),
		IntermediateKeyAlgorithm:   types.StringNull(),
		CA:                         caObj,
	}
	if x509.IntermediateCertificateTtl != nil {
		model.IntermediateCertificateTTL = types.Int64Value(int64(*x509.IntermediateCertificateTtl))
	}
	if x509.IntermediateKeyAlgorithm != nil {
		model.IntermediateKeyAlgorithm = types.StringValue(string(*x509.IntermediateKeyAlgorithm))
	}

	obj, objDiags := types.ObjectValueFrom(ctx, x509AttrTypes, model)
	diags.Append(objDiags...)
	return obj, diags
}

func trustDomainCAObject(ctx context.Context, ca *swaclient.X509CAConfiguration) (types.Object, diag.Diagnostics) {
	cfgObj := types.ObjectNull(x509CAConfigAttrTypes)
	var diags diag.Diagnostics
	if ca.Config != (swaclient.BuiltinRootCAConfiguration{}) {
		cfgObj, diags = types.ObjectValueFrom(ctx, x509CAConfigAttrTypes, &X509CAConfigModel{
			RootCATTL:                   types.Int64Value(int64(ca.Config.RootCaTtl)),
			RootKeyAlgorithm:            types.StringValue(string(ca.Config.RootKeyAlgorithm)),
			RootRotationTriggerFraction: types.Float64Value(ca.Config.RootRotationTriggerFraction),
		})
		if diags.HasError() {
			return types.ObjectNull(x509CAAttrTypes), diags
		}
	}
	caObj, caDiags := types.ObjectValueFrom(ctx, x509CAAttrTypes, &X509CAModel{
		Type:   types.StringValue(string(ca.Type)),
		Config: cfgObj,
	})
	diags.Append(caDiags...)
	return caObj, diags
}

// x509InputFromModel converts an x509 block into PATCH request fields. Null
// and unknown values (Optional+Computed attributes the user left unset) are
// omitted so the server applies its own defaults.
func x509InputFromModel(ctx context.Context, m *X509ConfigModel) (swaclient.UpdateX509ConfigurationInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	return swaclient.UpdateX509ConfigurationInput{
		WorkloadTtl:                int32PtrFromInt64(m.WorkloadTTL),
		IntermediateCertificateTtl: int32PtrFromInt64(m.IntermediateCertificateTTL),
		IntermediateKeyAlgorithm:   caKeyAlgorithmPtr(m.IntermediateKeyAlgorithm),
		Ca:                         x509CAInputFromModel(ctx, m.CA, &diags),
	}, diags
}

// createX509InputFromModel is the create-request counterpart to
// x509InputFromModel. The two input types are built separately so a generated
// client that diverges them cannot break compilation of unrelated code.
func createX509InputFromModel(ctx context.Context, m *X509ConfigModel) (swaclient.X509ConfigurationInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	return swaclient.X509ConfigurationInput{
		WorkloadTtl:                int32PtrFromInt64(m.WorkloadTTL),
		IntermediateCertificateTtl: int32PtrFromInt64(m.IntermediateCertificateTTL),
		IntermediateKeyAlgorithm:   caKeyAlgorithmPtr(m.IntermediateKeyAlgorithm),
		Ca:                         x509CAInputFromModel(ctx, m.CA, &diags),
	}, diags
}

func x509CAInputFromModel(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *swaclient.X509CAConfigurationInput {
	ca := modelFromObject[X509CAModel](ctx, obj, diags)
	if ca == nil {
		return nil
	}
	in := &swaclient.X509CAConfigurationInput{Type: swaclient.CAType(ca.Type.ValueString())}
	if cfg := modelFromObject[X509CAConfigModel](ctx, ca.Config, diags); cfg != nil {
		in.Config = &swaclient.BuiltinRootCAConfigurationInput{
			RootCaTtl:                   int32PtrFromInt64(cfg.RootCATTL),
			RootKeyAlgorithm:            caKeyAlgorithmPtr(cfg.RootKeyAlgorithm),
			RootRotationTriggerFraction: float64Ptr(cfg.RootRotationTriggerFraction),
		}
	}
	return in
}

// changedX509Input drops every field of plan that already holds the same
// value in state, so a PATCH carries only real changes. Resending unchanged
// values copied from state would be at best noise and at worst rejected, for
// instance an intermediate TTL that no longer satisfies a new workload TTL.
func changedX509Input(plan, state swaclient.UpdateX509ConfigurationInput) swaclient.UpdateX509ConfigurationInput {
	out := swaclient.UpdateX509ConfigurationInput{
		WorkloadTtl:                changedPtr(plan.WorkloadTtl, state.WorkloadTtl),
		IntermediateCertificateTtl: changedPtr(plan.IntermediateCertificateTtl, state.IntermediateCertificateTtl),
		IntermediateKeyAlgorithm:   changedPtr(plan.IntermediateKeyAlgorithm, state.IntermediateKeyAlgorithm),
	}
	if plan.Ca == nil {
		return out
	}

	var stateType swaclient.CAType
	var stateCfg *swaclient.BuiltinRootCAConfigurationInput
	if state.Ca != nil {
		stateType, stateCfg = state.Ca.Type, state.Ca.Config
	}
	cfg := changedCAConfig(plan.Ca.Config, stateCfg)
	// type is required whenever ca is sent.
	if plan.Ca.Type != stateType || cfg != nil {
		out.Ca = &swaclient.X509CAConfigurationInput{Type: plan.Ca.Type, Config: cfg}
	}
	return out
}

// changedCAConfig is the CA config counterpart to changedX509Input. It returns
// nil when nothing in plan differs from state.
func changedCAConfig(plan, state *swaclient.BuiltinRootCAConfigurationInput) *swaclient.BuiltinRootCAConfigurationInput {
	if plan == nil {
		return nil
	}
	var prior swaclient.BuiltinRootCAConfigurationInput
	if state != nil {
		prior = *state
	}
	changed := swaclient.BuiltinRootCAConfigurationInput{
		RootCaTtl:                   changedPtr(plan.RootCaTtl, prior.RootCaTtl),
		RootKeyAlgorithm:            changedPtr(plan.RootKeyAlgorithm, prior.RootKeyAlgorithm),
		RootRotationTriggerFraction: changedPtr(plan.RootRotationTriggerFraction, prior.RootRotationTriggerFraction),
	}
	if changed == (swaclient.BuiltinRootCAConfigurationInput{}) {
		return nil
	}
	return &changed
}

// caKeyAlgorithmPtr returns nil for null/unknown values so they are omitted
// from the request.
func caKeyAlgorithmPtr(v types.String) *swaclient.CAKeyAlgorithm {
	if !isSet(v) {
		return nil
	}
	return new(swaclient.CAKeyAlgorithm(v.ValueString()))
}

// caKeyAlgorithmValidator accepts the members of the generated CAKeyAlgorithm
// enum, so a regenerated client picks up new algorithms without a second list
// to maintain here.
type caKeyAlgorithmValidator struct{}

func (caKeyAlgorithmValidator) Description(_ context.Context) string {
	return "value must be a supported CA key algorithm"
}

func (v caKeyAlgorithmValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (caKeyAlgorithmValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if !isSet(req.ConfigValue) {
		return
	}
	if !swaclient.CAKeyAlgorithm(req.ConfigValue.ValueString()).Valid() {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid CA key algorithm",
			fmt.Sprintf("%q is not a supported key algorithm.", req.ConfigValue.ValueString()))
	}
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
	return &TrustDomainResource{
		resourceBase[swaclient.ClientWithResponsesInterface]{
			swaComponent(
				"conjur_swa_trust_domain",
				CapabilitySWA,
			),
		},
	}
}

func (r *TrustDomainResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
				MarkdownDescription: "The trust domain name (e.g., `prod.example.org`). Case-sensitive; must be 1-60 characters and may include letters, numbers, periods, underscores, and hyphens only.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 60),
					stringvalidator.RegexMatches(swaResourceNamePattern, "must contain only letters, numbers, periods, underscores, and hyphens"),
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
						MarkdownDescription: "The signature algorithm for JWT-SVIDs. One of `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`. Defaults to `RS512`.",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("RS512"),
						Validators: []validator.String{
							stringvalidator.OneOf("ES256", "ES384", "ES512", "RS256", "RS384", "RS512"),
						},
					},
					"signing_key_type": schema.StringAttribute{
						MarkdownDescription: "The signing key type for JWT-SVIDs. One of `EC_P256`, `EC_P384`, `EC_P521`, `RSA_2048`, `RSA_4096`. Defaults to `RSA_4096`.",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("RSA_4096"),
						Validators: []validator.String{
							stringvalidator.OneOf("EC_P256", "EC_P384", "EC_P521", "RSA_2048", "RSA_4096"),
						},
					},
					"signing_key_ttl": schema.Int64Attribute{
						MarkdownDescription: "Signing key lifetime in seconds. Between 3600 and 2592000. Defaults to 86400.",
						Optional:            true,
						Computed:            true,
						Default:             int64default.StaticInt64(86400),
						Validators: []validator.Int64{
							int64validator.Between(3600, 2592000),
						},
					},
					"token_ttl": schema.Int64Attribute{
						MarkdownDescription: "JWT-SVID lifetime in seconds. Between 60 and 86400. Defaults to 300.",
						Optional:            true,
						Computed:            true,
						Default:             int64default.StaticInt64(300),
						Validators: []validator.Int64{
							int64validator.Between(60, 86400),
						},
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
						MarkdownDescription: "Workload X.509 SVID lifetime in seconds. Between 600 and 86400. Defaults to 3600.",
						Optional:            true,
						Computed:            true,
						Default:             int64default.StaticInt64(3600),
						Validators: []validator.Int64{
							int64validator.Between(600, 86400),
						},
					},
					"intermediate_certificate_ttl": schema.Int64Attribute{
						MarkdownDescription: "Lifetime of an intermediate CA certificate in seconds. Between 86400 and 604800, and at least twice `workload_ttl`. When omitted on create, the server default applies: 24 hours, or twice `workload_ttl` when that is longer. When omitted on update, the current value is kept, so raising `workload_ttl` past half of it requires setting this attribute too.",
						Optional:            true,
						Computed:            true,
						PlanModifiers: []planmodifier.Int64{
							int64planmodifier.UseStateForUnknown(),
						},
						Validators: []validator.Int64{
							int64validator.Between(86400, 604800),
						},
					},
					"intermediate_key_algorithm": schema.StringAttribute{
						MarkdownDescription: "Key algorithm used for intermediate CA certificates. One of `EC_P256`, `EC_P384`, `RSA_2048`, `RSA_4096`. When omitted, the server default applies (`EC_P256`).",
						Optional:            true,
						Computed:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
						Validators: []validator.String{
							caKeyAlgorithmValidator{},
						},
					},
					"ca": schema.SingleNestedAttribute{
						MarkdownDescription: "Certificate authority that signs the trust domain's intermediate CA certificates. When omitted, the server configures the built-in CA with its defaults.",
						Optional:            true,
						Computed:            true,
						PlanModifiers: []planmodifier.Object{
							objectplanmodifier.UseStateForUnknown(),
						},
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								MarkdownDescription: "The certificate authority type. Only `builtin` is supported: the root CA that SWA manages for the trust domain.",
								Required:            true,
								Validators: []validator.String{
									stringvalidator.OneOf(string(swaclient.CATypeBuiltin)),
								},
							},
							"config": schema.SingleNestedAttribute{
								MarkdownDescription: "Settings of the built-in root CA. Omitted attributes take the server defaults.",
								Optional:            true,
								Computed:            true,
								PlanModifiers: []planmodifier.Object{
									objectplanmodifier.UseStateForUnknown(),
								},
								Attributes: map[string]schema.Attribute{
									"root_ca_ttl": schema.Int64Attribute{
										MarkdownDescription: "Lifetime of a root CA certificate in seconds. Between 10368000 and 315360000, and at least twice `intermediate_certificate_ttl`. When omitted, the server default applies (120 days). A change applies only to the next root CA generation: existing generations keep their lifetime, so this value can differ from the certificate that is currently signing.",
										Optional:            true,
										Computed:            true,
										PlanModifiers: []planmodifier.Int64{
											int64planmodifier.UseStateForUnknown(),
										},
										Validators: []validator.Int64{
											int64validator.Between(10368000, 315360000),
										},
									},
									"root_key_algorithm": schema.StringAttribute{
										MarkdownDescription: "Key algorithm used for new root CA generations. One of `EC_P256`, `EC_P384`, `RSA_2048`, `RSA_4096`. When omitted, the server default applies (`EC_P384`). A change applies only to the next root CA generation: the certificate that is currently signing keeps its algorithm.",
										Optional:            true,
										Computed:            true,
										PlanModifiers: []planmodifier.String{
											stringplanmodifier.UseStateForUnknown(),
										},
										Validators: []validator.String{
											caKeyAlgorithmValidator{},
										},
									},
									"root_rotation_trigger_fraction": schema.Float64Attribute{
										MarkdownDescription: "How far into a root CA's lifetime the next generation is provisioned, as a fraction of its total validity. Between 0.5 and 0.9. When omitted, the server default applies (0.75). The value is stored but takes effect only once automatic root CA rotation is available.",
										Optional:            true,
										Computed:            true,
										PlanModifiers: []planmodifier.Float64{
											float64planmodifier.UseStateForUnknown(),
										},
										Validators: []validator.Float64{
											float64validator.Between(0.5, 0.9),
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

// ValidateConfig enforces at plan time that an explicit intermediate TTL is at
// least twice an explicit workload TTL. Values left to server defaults are
// checked by the API itself. The root_ca_ttl rule (at least twice the
// intermediate TTL) needs no check: the attribute ranges already guarantee it.
func (r *TrustDomainResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	x509 := path.Root("x509")
	var workloadTTL, intermediateTTL types.Int64
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, x509.AtName("workload_ttl"), &workloadTTL)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, x509.AtName("intermediate_certificate_ttl"), &intermediateTTL)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if detail := intermediateTTLError(workloadTTL, intermediateTTL); detail != "" {
		resp.Diagnostics.AddAttributeError(x509.AtName("intermediate_certificate_ttl"), "Invalid intermediate_certificate_ttl", detail)
	}
}

// intermediateTTLError returns the error detail when both TTLs are known and
// the intermediate TTL is shorter than twice the workload TTL, else "".
func intermediateTTLError(workloadTTL, intermediateTTL types.Int64) string {
	if !isSet(workloadTTL) || !isSet(intermediateTTL) || intermediateTTL.ValueInt64() >= 2*workloadTTL.ValueInt64() {
		return ""
	}
	return fmt.Sprintf("intermediate_certificate_ttl must be at least twice workload_ttl: %d is less than 2 x %d.",
		intermediateTTL.ValueInt64(), workloadTTL.ValueInt64())
}

// ModifyPlan rejects a plan whose intermediate_certificate_ttl is shorter than
// twice workload_ttl. ValidateConfig only sees values written in the
// configuration. Here the intermediate TTL can also be the stored value carried
// into the plan, which is what happens when workload_ttl is raised and the
// intermediate TTL is not configured. A PATCH is validated against the stored
// value and the server does not recompute it, so that plan would fail at apply
// with a 422. Nothing is computed or sent on the user's behalf: the user has to
// raise the intermediate TTL explicitly.
func (r *TrustDomainResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}

	x509 := path.Root("x509")
	var workloadTTL, intermediateTTL, configuredTTL types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, x509.AtName("workload_ttl"), &workloadTTL)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, x509.AtName("intermediate_certificate_ttl"), &intermediateTTL)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, x509.AtName("intermediate_certificate_ttl"), &configuredTTL)...)
	if resp.Diagnostics.HasError() {
		return
	}

	detail := intermediateTTLError(workloadTTL, intermediateTTL)
	if detail == "" {
		return
	}
	// A configured value was already rejected by ValidateConfig, so reaching
	// here with one set only repeats that error.
	if configuredTTL.IsNull() {
		detail += fmt.Sprintf(" The current intermediate_certificate_ttl is kept when it is not configured, so set x509.intermediate_certificate_ttl to at least %d together with x509.workload_ttl.", 2*workloadTTL.ValueInt64())
	}
	resp.Diagnostics.AddAttributeError(x509.AtName("intermediate_certificate_ttl"), "Invalid intermediate_certificate_ttl", detail)
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

	if x509Cfg := modelFromObject[X509ConfigModel](ctx, plan.X509, &resp.Diagnostics); x509Cfg != nil {
		in, diags := createX509InputFromModel(ctx, x509Cfg)
		resp.Diagnostics.Append(diags...)
		createReq.X509 = &in
	}
	if resp.Diagnostics.HasError() {
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

	// The prior state lets the PATCH carry only x509 values that changed.
	var state TrustDomainResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
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

	if x509Cfg := modelFromObject[X509ConfigModel](ctx, plan.X509, &resp.Diagnostics); x509Cfg != nil {
		planIn, diags := x509InputFromModel(ctx, x509Cfg)
		resp.Diagnostics.Append(diags...)
		var stateIn swaclient.UpdateX509ConfigurationInput
		if stateCfg := modelFromObject[X509ConfigModel](ctx, state.X509, &resp.Diagnostics); stateCfg != nil {
			stateIn, diags = x509InputFromModel(ctx, stateCfg)
			resp.Diagnostics.Append(diags...)
		}
		if changed := changedX509Input(planIn, stateIn); changed != (swaclient.UpdateX509ConfigurationInput{}) {
			updateReq.X509 = &changed
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Nothing differs from state (for example a change that only touched
	// computed values), so there is nothing to PATCH.
	if updateReq.Jwt == nil && updateReq.X509 == nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
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
