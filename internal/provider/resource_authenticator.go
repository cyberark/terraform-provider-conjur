package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &ConjurAuthenticatorResource{}
	_ resource.ResourceWithImportState = &ConjurAuthenticatorResource{}
	_ resource.ResourceWithConfigure   = &ConjurAuthenticatorResource{}
)

func NewConjurAuthenticatorResource() resource.Resource {
	return &ConjurAuthenticatorResource{}
}

// ConjurAuthenticatorResource defines the resource implementation.
type ConjurAuthenticatorResource struct {
	client api.ClientV2
}

// ConjurAuthenticatorResourceModel describes the resource data model.
type ConjurAuthenticatorResourceModel struct {
	Type        types.String                  `tfsdk:"type"`
	Name        types.String                  `tfsdk:"name"`
	Subtype     types.String                  `tfsdk:"subtype"`
	Enabled     types.Bool                    `tfsdk:"enabled"`
	Owner       types.Object                  `tfsdk:"owner"`
	Data        *ConjurAuthenticatorDataModel `tfsdk:"data"`
	Annotations map[string]string             `tfsdk:"annotations"`
}

type ConjurAuthenticatorDataModel struct {
	Audience   types.String                      `tfsdk:"audience"`
	JwksURI    types.String                      `tfsdk:"jwks_uri"`
	Issuer     types.String                      `tfsdk:"issuer"`
	CACert     types.String                      `tfsdk:"ca_cert"`
	PublicKeys types.String                      `tfsdk:"public_keys"`
	Identity   *ConjurAuthenticatorIdentityModel `tfsdk:"identity"`
}

type ConjurAuthenticatorIdentityModel struct {
	IdentityPath     types.String      `tfsdk:"identity_path"`
	TokenAppProperty types.String      `tfsdk:"token_app_property"`
	ClaimAliases     map[string]string `tfsdk:"claim_aliases"`
	EnforcedClaims   []string          `tfsdk:"enforced_claims"`
}

func (r *ConjurAuthenticatorResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_authenticator"
}

func (r *ConjurAuthenticatorResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "CyberArk Secrets Manager authenticator resource",

		Attributes: map[string]schema.Attribute{
			"type": schema.StringAttribute{
				MarkdownDescription: "The authenticator type (e.g., jwt, ldap, oidc)",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the authenticator",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"subtype": schema.StringAttribute{
				MarkdownDescription: "Authenticator subtype (e.g., github)",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the authenticator is enabled",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"annotations": schema.MapAttribute{
				MarkdownDescription: "Key-value annotations for the authenticator",
				Optional:            true,
				ElementType:         types.StringType,
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.RequiresReplace(),
				},
			},
			"owner": schema.SingleNestedAttribute{
				MarkdownDescription: "Owner of the authenticator",
				Optional:            true,
				Computed:            true,
				Attributes: map[string]schema.Attribute{
					"kind": schema.StringAttribute{
						MarkdownDescription: "Owner kind (user, group, etc.)",
						Optional:            true,
						Computed:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"id": schema.StringAttribute{
						MarkdownDescription: "Owner identifier",
						Optional:            true,
						Computed:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
				},
			},
			"data": schema.SingleNestedAttribute{
				MarkdownDescription: "Authenticator configuration data",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"audience": schema.StringAttribute{
						MarkdownDescription: "JWT audience",
						Optional:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"jwks_uri": schema.StringAttribute{
						MarkdownDescription: "JWKS URI",
						Optional:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"issuer": schema.StringAttribute{
						Optional: true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"ca_cert": schema.StringAttribute{
						MarkdownDescription: "CA certificate",
						Optional:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"public_keys": schema.StringAttribute{
						MarkdownDescription: "Public keys",
						Optional:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"identity": schema.SingleNestedAttribute{
						MarkdownDescription: "Identity configuration",
						Optional:            true,
						Attributes: map[string]schema.Attribute{
							"identity_path": schema.StringAttribute{
								MarkdownDescription: "Identity path",
								Optional:            true,
								PlanModifiers: []planmodifier.String{
									stringplanmodifier.RequiresReplace(),
								},
							},
							"token_app_property": schema.StringAttribute{
								MarkdownDescription: "Token app property",
								Optional:            true,
								PlanModifiers: []planmodifier.String{
									stringplanmodifier.RequiresReplace(),
								},
							},
							"claim_aliases": schema.MapAttribute{
								MarkdownDescription: "Claim aliases mapping",
								Optional:            true,
								ElementType:         types.StringType,
								PlanModifiers: []planmodifier.Map{
									mapplanmodifier.RequiresReplace(),
								},
							},
							"enforced_claims": schema.ListAttribute{
								MarkdownDescription: "List of enforced claims",
								Optional:            true,
								ElementType:         types.StringType,
								PlanModifiers: []planmodifier.List{
									listplanmodifier.RequiresReplace(),
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *ConjurAuthenticatorResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ConjurAuthenticatorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConjurAuthenticatorResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	newAuthenticator, err := r.buildAuthenticatorPayload(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Authenticator Payload", fmt.Sprintf("Could not build authenticator payload: %s", err))
		return
	}

	authenticatorResp, err := r.client.CreateAuthenticator(newAuthenticator)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create authenticator, got error: %s", err))
		return
	}

	// Parse the actual API response into the state (including computed attributes)
	err = r.parseAuthenticatorResponse(authenticatorResp, &data)
	if err != nil {
		resp.Diagnostics.AddError("Error Parsing Authenticator Response", fmt.Sprintf("Could not parse authenticator response: %s", err))
		return
	}

	tflog.Trace(ctx, "created authenticator resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurAuthenticatorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConjurAuthenticatorResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	authenticatorResponse, err := r.client.GetAuthenticator(data.Type.ValueString(), data.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read authenticator, got error: %s", err))
		return
	}

	err = r.parseAuthenticatorResponse(authenticatorResponse, &data)
	if err != nil {
		resp.Diagnostics.AddError("Error Parsing Authenticator Response", fmt.Sprintf("Could not parse authenticator response: %s", err))
		return
	}

	tflog.Trace(ctx, "read authenticator resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)

}

func (r *ConjurAuthenticatorResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ConjurAuthenticatorResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read the stated data into the model
	var state ConjurAuthenticatorResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Enable/disable the authenticator
	err := r.client.EnableAuthenticator(data.Type.ValueString(), data.Name.ValueString(), data.Enabled.ValueBool())
	if err != nil {
		resp.Diagnostics.AddWarning("Unable to update the authenticator", fmt.Sprintf("Could not update authenticator for %q: %s", data.Name.ValueString(), err))
	}

	data.Owner = state.Owner // Owner may be set in state via the API response, but not reflected in HCL data so we set it manually

	tflog.Trace(ctx, "updated authenticator resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurAuthenticatorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConjurAuthenticatorResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteAuthenticator(data.Type.ValueString(), data.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete authenticator, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "deleted authenticator resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurAuthenticatorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			"Expected format: <type>:<name>",
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("type"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[1])...)
}

// buildAuthenticatorPayload maps the resource model to an API payload
func (r *ConjurAuthenticatorResource) buildAuthenticatorPayload(data *ConjurAuthenticatorResourceModel) (*conjurapi.AuthenticatorBase, error) {
	authenticator := conjurapi.AuthenticatorBase{
		Type: data.Type.ValueString(),
		Name: data.Name.ValueString(),
	}

	// Top level optional fields (only set if not null/unknown)
	if strPtr := valueStringPtr(data.Subtype); strPtr != nil {
		authenticator.Subtype = strPtr
	}
	if boolPtr := valueBoolPtr(data.Enabled); boolPtr != nil {
		authenticator.Enabled = boolPtr
	}

	if !data.Owner.IsNull() && !data.Owner.IsUnknown() {
		authenticator.Owner = &conjurapi.AuthOwner{
			Kind: data.Owner.Attributes()["kind"].(types.String).ValueString(),
			ID:   data.Owner.Attributes()["id"].(types.String).ValueString(),
		}
	}

	if authenticatorData, err := buildDataPayload(data.Data); err != nil {
		return nil, err
	} else if len(authenticatorData) > 0 {
		authenticator.Data = authenticatorData
	}

	if len(data.Annotations) > 0 {
		authenticator.Annotations = data.Annotations
	}

	return &authenticator, nil
}

// buildDataPayload creates a nested Authenticator.Data object if provided
func buildDataPayload(d *ConjurAuthenticatorDataModel) (map[string]interface{}, error) {
	if d == nil {
		return nil, nil
	}

	payload := map[string]interface{}{}
	addIfNotNull(payload, "audience", d.Audience)
	addIfNotNull(payload, "jwks_uri", d.JwksURI)
	addIfNotNull(payload, "issuer", d.Issuer)
	addIfNotNull(payload, "ca_cert", d.CACert)

	if !d.PublicKeys.IsNull() && !d.PublicKeys.IsUnknown() {
		var obj interface{}
		if err := json.Unmarshal([]byte(d.PublicKeys.ValueString()), &obj); err != nil {
			return nil, fmt.Errorf("invalid JSON in public_keys: %w", err)
		}
		payload["public_keys"] = obj
	}

	if id := buildIdentityPayload(d.Identity); len(id) > 0 {
		payload["identity"] = id
	}

	return payload, nil
}

// buildDataPayload creates a nested Authenticator.Data.Identity object if provided
func buildIdentityPayload(identity *ConjurAuthenticatorIdentityModel) map[string]interface{} {
	if identity == nil {
		return nil
	}
	payload := map[string]interface{}{}

	addIfNotNull(payload, "identity_path", identity.IdentityPath)
	addIfNotNull(payload, "token_app_property", identity.TokenAppProperty)

	if len(identity.ClaimAliases) > 0 {
		payload["claim_aliases"] = identity.ClaimAliases
	}
	if len(identity.EnforcedClaims) > 0 {
		payload["enforced_claims"] = identity.EnforcedClaims
	}
	return payload
}

// parseAuthenticatorResponse maps the API response to the resource model
func (r *ConjurAuthenticatorResource) parseAuthenticatorResponse(authenticator *conjurapi.AuthenticatorResponse, data *ConjurAuthenticatorResourceModel) error {
	data.Type = types.StringValue(authenticator.Type)
	data.Name = types.StringValue(authenticator.Name)
	data.Subtype = stringOrNull(authenticator.Subtype)
	data.Enabled = boolOrNull(authenticator.Enabled)

	if authenticator.Owner != nil {
		ownerAttrs := map[string]attr.Value{
			"kind": types.StringValue(authenticator.Owner.Kind),
			"id":   types.StringValue(authenticator.Owner.ID),
		}
		data.Owner = types.ObjectValueMust(map[string]attr.Type{
			"kind": types.StringType,
			"id":   types.StringType,
		}, ownerAttrs)
	} else {
		data.Owner = types.ObjectNull(map[string]attr.Type{
			"kind": types.StringType,
			"id":   types.StringType,
		})
	}

	if authenticatorData, err := parseDataFromMap(authenticator.Data); err != nil {
		return err
	} else {
		data.Data = authenticatorData
	}

	data.Annotations = authenticator.Annotations
	return nil
}

// parseDataFromMap maps the API response nested Authenticator.Data object to the resource model
func parseDataFromMap(data map[string]interface{}) (*ConjurAuthenticatorDataModel, error) {
	if data == nil {
		return nil, nil
	}

	authenticatorData := &ConjurAuthenticatorDataModel{
		Audience: stringFromMap(data, "audience"),
		JwksURI:  stringFromMap(data, "jwks_uri"),
		Issuer:   stringFromMap(data, "issuer"),
		CACert:   stringFromMap(data, "ca_cert"),
	}

	if pk, ok := data["public_keys"]; ok {
		raw, err := json.Marshal(pk)
		if err != nil {
			return nil, fmt.Errorf("invalid JSON in public_keys: %w", err)
		}
		authenticatorData.PublicKeys = types.StringValue(string(raw))
	} else {
		authenticatorData.PublicKeys = types.StringNull()
	}

	authenticatorData.Identity = parseIdentityFromMap(data)

	return authenticatorData, nil
}

// parseIdentityFromMap maps the API response nested Authenticator.Data.Identity object to the resource model
func parseIdentityFromMap(data map[string]interface{}) *ConjurAuthenticatorIdentityModel {
	raw, ok := data["identity"].(map[string]interface{})
	if !ok {
		return nil
	}

	im := ConjurAuthenticatorIdentityModel{
		IdentityPath:     stringFromMap(raw, "identity_path"),
		TokenAppProperty: stringFromMap(raw, "token_app_property"),
	}

	if aliases, ok := raw["claim_aliases"].(map[string]interface{}); ok {
		im.ClaimAliases = make(map[string]string, len(aliases))
		for k, v := range aliases {
			if str, ok := v.(string); ok {
				im.ClaimAliases[k] = str
			}
		}
	}
	if enforced, ok := raw["enforced_claims"].([]interface{}); ok {
		for _, v := range enforced {
			if str, ok := v.(string); ok {
				im.EnforcedClaims = append(im.EnforcedClaims, str)
			}
		}
	}
	return &im
}

// Helper functions to ensure properly handling of null/unknown/unset values
func valueStringPtr(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	return v.ValueStringPointer()
}

func valueBoolPtr(v types.Bool) *bool {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	return v.ValueBoolPointer()
}

func addIfNotNull(m map[string]interface{}, key string, v types.String) {
	if !v.IsNull() && !v.IsUnknown() {
		m[key] = v.ValueString()
	}
}

func stringOrNull(s *string) types.String {
	if s != nil {
		return types.StringValue(*s)
	}
	return types.StringNull()
}

func boolOrNull(b *bool) types.Bool {
	if b != nil {
		return types.BoolValue(*b)
	}
	return types.BoolNull()
}

func stringFromMap(m map[string]interface{}, key string) types.String {
	if val, ok := m[key].(string); ok {
		return types.StringValue(val)
	}
	return types.StringNull()
}
