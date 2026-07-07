package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                   = &ServerResource{}
	_ resource.ResourceWithConfigure      = &ServerResource{}
	_ resource.ResourceWithImportState    = &ServerResource{}
	_ resource.ResourceWithValidateConfig = &ServerResource{}
)

type ServerResource struct {
	client swaclient.ClientWithResponsesInterface
}

type ServerResourceModel struct {
	ID            types.String               `tfsdk:"id"`
	Name          types.String               `tfsdk:"name"`
	ServerGroupID types.String               `tfsdk:"server_group_id"`
	AuthnID       types.String               `tfsdk:"authn_id"`
	Auth          *ServerAuthenticationModel `tfsdk:"auth"`
}

type ServerAuthenticationModel struct {
	Type       types.String                       `tfsdk:"type"`
	Subject    types.String                       `tfsdk:"subject"`
	Audience   types.String                       `tfsdk:"audience"`
	JWKSURI    types.String                       `tfsdk:"jwks_uri"`
	Issuer     types.String                       `tfsdk:"issuer"`
	CACert     types.String                       `tfsdk:"ca_cert"`
	PublicKeys types.String                       `tfsdk:"public_keys"`
	Identity   *ServerAuthenticationIdentityModel `tfsdk:"identity"`
}

type ServerAuthenticationIdentityModel struct {
	ClaimAliases     types.Map    `tfsdk:"claim_aliases"`
	EnforcedClaims   types.List   `tfsdk:"enforced_claims"`
	IdentityPath     types.String `tfsdk:"identity_path"`
	TokenAppProperty types.String `tfsdk:"token_app_property"`
}

func NewServerResource() resource.Resource {
	return &ServerResource{}
}

func stringValueFromAuthData(data map[string]any, key string) types.String {
	v, ok := data[key]
	if !ok {
		return types.StringNull()
	}
	s, ok := v.(string)
	if !ok {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func asStringSlice(v any) ([]string, bool) {
	if values, ok := v.([]string); ok {
		return values, true
	}
	rawValues, ok := v.([]any)
	if !ok {
		return nil, false
	}
	values := make([]string, 0, len(rawValues))
	for _, raw := range rawValues {
		s, ok := raw.(string)
		if !ok {
			return nil, false
		}
		values = append(values, s)
	}
	return values, true
}

func asStringMap(v any) (map[string]string, bool) {
	if values, ok := v.(map[string]string); ok {
		return values, true
	}
	rawValues, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	values := make(map[string]string, len(rawValues))
	for key, raw := range rawValues {
		s, ok := raw.(string)
		if !ok {
			return nil, false
		}
		values[key] = s
	}
	return values, true
}

func knownStringValue(v types.String) bool {
	return !v.IsNull() && !v.IsUnknown()
}

func nonEmptyKnownStringValue(v types.String) bool {
	return knownStringValue(v) && v.ValueString() != ""
}

func stringPointerFromValue(v types.String) *string {
	if !knownStringValue(v) {
		return nil
	}
	return new(v.ValueString())
}

func setMapValueIfNotNil[T any](data map[string]any, key string, value *T) {
	if value != nil {
		data[key] = *value
	}
}

func mapValueFromIdentityField(ctx context.Context, raw any, field string) (types.Map, error) {
	values, ok := asStringMap(raw)
	if !ok {
		return types.MapNull(types.StringType), fmt.Errorf("invalid auth.identity.%s in response", field)
	}
	value, diags := types.MapValueFrom(ctx, types.StringType, values)
	if diags.HasError() {
		return types.MapNull(types.StringType), fmt.Errorf("failed to convert auth.identity.%s from response", field)
	}
	return value, nil
}

func listValueFromIdentityField(ctx context.Context, raw any, field string) (types.List, error) {
	values, ok := asStringSlice(raw)
	if !ok {
		return types.ListNull(types.StringType), fmt.Errorf("invalid auth.identity.%s in response", field)
	}
	value, diags := types.ListValueFrom(ctx, types.StringType, values)
	if diags.HasError() {
		return types.ListNull(types.StringType), fmt.Errorf("failed to convert auth.identity.%s from response", field)
	}
	return value, nil
}

func buildCreateServerIdentity(ctx context.Context, model *ServerAuthenticationIdentityModel) (*struct {
	ClaimAliases     *map[string]string `json:"claim_aliases,omitempty"`
	EnforcedClaims   *[]string          `json:"enforced_claims,omitempty"`
	IdentityPath     *string            `json:"identity_path,omitempty"`
	TokenAppProperty *string            `json:"token_app_property,omitempty"`
}, diag.Diagnostics) {
	var diags diag.Diagnostics
	if model == nil {
		return nil, diags
	}

	identity := &struct {
		ClaimAliases     *map[string]string `json:"claim_aliases,omitempty"`
		EnforcedClaims   *[]string          `json:"enforced_claims,omitempty"`
		IdentityPath     *string            `json:"identity_path,omitempty"`
		TokenAppProperty *string            `json:"token_app_property,omitempty"`
	}{}

	if !model.ClaimAliases.IsNull() && !model.ClaimAliases.IsUnknown() {
		aliases := make(map[string]string)
		diags.Append(model.ClaimAliases.ElementsAs(ctx, &aliases, false)...)
		if diags.HasError() {
			return nil, diags
		}
		identity.ClaimAliases = &aliases
	}

	if !model.EnforcedClaims.IsNull() && !model.EnforcedClaims.IsUnknown() {
		var claims []string
		diags.Append(model.EnforcedClaims.ElementsAs(ctx, &claims, false)...)
		if diags.HasError() {
			return nil, diags
		}
		identity.EnforcedClaims = &claims
	}

	identity.IdentityPath = stringPointerFromValue(model.IdentityPath)
	identity.TokenAppProperty = stringPointerFromValue(model.TokenAppProperty)

	return identity, diags
}

func splitServerGroupID(id string) (trustDomainName, serverGroupName string, err error) {
	parts, err := splitSWAID(id, 2, "trust_domain_name/server_group_name")
	if err != nil {
		return "", "", err
	}
	return parts[0], parts[1], nil
}

func validateCreateServerAuthConfig(auth *ServerAuthenticationModel, diags *diag.Diagnostics) bool {
	if auth == nil {
		diags.AddError("Missing auth configuration", "auth block is required")
		return false
	}

	authType := auth.Type.ValueString()
	if authType != "JWT" {
		diags.AddError(
			"Invalid auth type",
			fmt.Sprintf("Only 'JWT' authentication type is supported, got: %s", authType),
		)
		return false
	}

	hasJWKSURI := nonEmptyKnownStringValue(auth.JWKSURI)
	hasPublicKeys := nonEmptyKnownStringValue(auth.PublicKeys)
	hasIssuer := nonEmptyKnownStringValue(auth.Issuer)

	if !hasJWKSURI && !hasPublicKeys {
		diags.AddError(
			"Invalid auth configuration",
			"At least one of auth.jwks_uri or auth.public_keys must be set.",
		)
		return false
	}

	if hasPublicKeys && !hasIssuer {
		diags.AddError(
			"Invalid auth configuration",
			"auth.issuer is required when auth.public_keys is set.",
		)
		return false
	}

	if auth.Identity != nil {
		hasIdentityPath := nonEmptyKnownStringValue(auth.Identity.IdentityPath)
		hasTokenAppProperty := nonEmptyKnownStringValue(auth.Identity.TokenAppProperty)
		if hasIdentityPath != hasTokenAppProperty {
			diags.AddError(
				"Invalid auth.identity configuration",
				"auth.identity.identity_path and auth.identity.token_app_property must be set together.",
			)
			return false
		}
	}

	return true
}

func buildCreateServerJWTAuthData(ctx context.Context, auth *ServerAuthenticationModel) (swaclient.CreateServerJWTAuthenticationData, diag.Diagnostics) {
	var diags diag.Diagnostics

	jwtAuthData := swaclient.CreateServerJWTAuthenticationData{
		Sub: auth.Subject.ValueString(),
	}
	jwtAuthData.JwksUri = stringPointerFromValue(auth.JWKSURI)
	jwtAuthData.Issuer = stringPointerFromValue(auth.Issuer)
	jwtAuthData.Audience = stringPointerFromValue(auth.Audience)
	jwtAuthData.CaCert = stringPointerFromValue(auth.CACert)

	if knownStringValue(auth.PublicKeys) {
		var pk map[string]any
		if err := json.Unmarshal([]byte(auth.PublicKeys.ValueString()), &pk); err != nil {
			diags.AddError("Invalid public_keys JSON", err.Error())
			return jwtAuthData, diags
		}
		jwtAuthData.PublicKeys = &pk
	}

	identity, identityDiags := buildCreateServerIdentity(ctx, auth.Identity)
	diags.Append(identityDiags...)
	if diags.HasError() {
		return jwtAuthData, diags
	}
	if identity != nil {
		jwtAuthData.Identity = identity
	}

	return jwtAuthData, diags
}

func serverAuthFromCreateResponse(auth swaclient.CreateServerAuthentication) (*swaclient.ServerAuthentication, error) {
	jwtData, err := auth.Data.AsCreateServerJWTAuthenticationData()
	if err != nil {
		// Some API responses omit authentication.data; keep plan-auth values in that case.
		return nil, nil
	}

	data := map[string]any{
		"sub": jwtData.Sub,
	}
	setMapValueIfNotNil(data, "audience", jwtData.Audience)
	setMapValueIfNotNil(data, "jwks_uri", jwtData.JwksUri)
	setMapValueIfNotNil(data, "issuer", jwtData.Issuer)
	setMapValueIfNotNil(data, "ca_cert", jwtData.CaCert)
	setMapValueIfNotNil(data, "public_keys", jwtData.PublicKeys)

	if jwtData.Identity != nil {
		identity := map[string]any{}
		setMapValueIfNotNil(identity, "claim_aliases", jwtData.Identity.ClaimAliases)
		setMapValueIfNotNil(identity, "enforced_claims", jwtData.Identity.EnforcedClaims)
		setMapValueIfNotNil(identity, "identity_path", jwtData.Identity.IdentityPath)
		setMapValueIfNotNil(identity, "token_app_property", jwtData.Identity.TokenAppProperty)
		if len(identity) > 0 {
			data["identity"] = identity
		}
	}

	return &swaclient.ServerAuthentication{
		Type: swaclient.ServerAuthenticationType(strings.ToLower(string(auth.Type))),
		Data: data,
	}, nil
}

func syncServerAuthFromResponse(ctx context.Context, state *ServerResourceModel, auth *swaclient.ServerAuthentication) error {
	if auth == nil {
		state.Auth = nil
		return nil
	}

	if state.Auth == nil {
		state.Auth = &ServerAuthenticationModel{}
	}

	state.Auth.Type = types.StringValue(strings.ToUpper(string(auth.Type)))
	state.Auth.Subject = stringValueFromAuthData(auth.Data, "sub")
	state.Auth.Audience = stringValueFromAuthData(auth.Data, "audience")
	state.Auth.JWKSURI = stringValueFromAuthData(auth.Data, "jwks_uri")
	state.Auth.Issuer = stringValueFromAuthData(auth.Data, "issuer")
	state.Auth.CACert = stringValueFromAuthData(auth.Data, "ca_cert")

	if publicKeys, ok := auth.Data["public_keys"]; ok {
		publicKeysJSON, err := json.Marshal(publicKeys)
		if err != nil {
			return fmt.Errorf("failed to marshal auth.public_keys from response: %w", err)
		}
		state.Auth.PublicKeys = types.StringValue(string(publicKeysJSON))
	} else {
		state.Auth.PublicKeys = types.StringNull()
	}

	identityRaw, ok := auth.Data["identity"]
	if !ok {
		state.Auth.Identity = nil
		return nil
	}

	identityMap, ok := identityRaw.(map[string]any)
	if !ok {
		state.Auth.Identity = nil
		return nil
	}

	identity := &ServerAuthenticationIdentityModel{
		ClaimAliases:     types.MapNull(types.StringType),
		EnforcedClaims:   types.ListNull(types.StringType),
		IdentityPath:     types.StringNull(),
		TokenAppProperty: types.StringNull(),
	}

	if claimAliasesRaw, ok := identityMap["claim_aliases"]; ok {
		claimAliasesValue, err := mapValueFromIdentityField(ctx, claimAliasesRaw, "claim_aliases")
		if err != nil {
			return err
		}
		identity.ClaimAliases = claimAliasesValue
	}

	if enforcedClaimsRaw, ok := identityMap["enforced_claims"]; ok {
		enforcedClaimsValue, err := listValueFromIdentityField(ctx, enforcedClaimsRaw, "enforced_claims")
		if err != nil {
			return err
		}
		identity.EnforcedClaims = enforcedClaimsValue
	}

	identity.IdentityPath = stringValueFromAuthData(identityMap, "identity_path")
	identity.TokenAppProperty = stringValueFromAuthData(identityMap, "token_app_property")

	state.Auth.Identity = identity

	return nil
}

func (r *ServerResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_swa_server"
}

func (r *ServerResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription:"Manages an SWA Server (agent).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription:"The unique identifier of the server.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription:"The name of the server.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 51),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"server_group_id": schema.StringAttribute{
				MarkdownDescription:"The ID of the server group this server belongs to.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"authn_id": schema.StringAttribute{
				MarkdownDescription:"Opaque Base64-encoded authenticator identifier for this server.",
				Computed:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"auth": schema.SingleNestedAttribute{
				MarkdownDescription:"Authentication configuration for the server.",
				Required:    true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplace(),
				},
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						MarkdownDescription:"The authentication type (e.g., 'JWT').",
						Required:    true,
					},
					"subject": schema.StringAttribute{
						MarkdownDescription:"The expected subject claim value from the workload JWT.",
						Required:    true,
					},
					"audience": schema.StringAttribute{
						MarkdownDescription:"The expected audience for JWT authentication.",
						Optional:    true,
					},
					"jwks_uri": schema.StringAttribute{
						MarkdownDescription:"The JWKS URI for JWT verification.",
						Optional:    true,
					},
					"issuer": schema.StringAttribute{
						MarkdownDescription:"The expected issuer for JWT authentication.",
						Optional:    true,
					},
					"ca_cert": schema.StringAttribute{
						MarkdownDescription:"PEM-encoded CA certificate for validating the JWKS provider's TLS certificate.",
						Optional:    true,
					},
					"public_keys": schema.StringAttribute{
						MarkdownDescription:`Inline JWKS as a JSON string. Format: {"type":"jwks","value":{"keys":[...]}}.`,
						Optional:    true,
					},
					"identity": schema.SingleNestedAttribute{
						MarkdownDescription:"Identity mapping configuration for the JWT authenticator.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"claim_aliases": schema.MapAttribute{
								MarkdownDescription:"A map of claim aliases to JWT claim names.",
								Optional:    true,
								ElementType: types.StringType,
							},
							"enforced_claims": schema.ListAttribute{
								MarkdownDescription:"A list of enforced claims.",
								Optional:    true,
								ElementType: types.StringType,
							},
							"identity_path": schema.StringAttribute{
								MarkdownDescription:"The workload's policy ID in Secrets Manager.",
								Optional:    true,
							},
							"token_app_property": schema.StringAttribute{
								MarkdownDescription:"The name of the JWT claim whose value identifies the workload.",
								Optional:    true,
							},
						},
					},
				},
			},
		},
	}
}

func (r *ServerResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data ServerResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	validateCreateServerAuthConfig(data.Auth, &resp.Diagnostics)
}

func (r *ServerResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, ok := configureSWAClient(req, resp)
	if !ok {
		return
	}
	r.client = client
}

func (r *ServerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var plan ServerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	trustDomainName, serverGroupName, err := splitServerGroupID(plan.ServerGroupID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid server group ID",
			err.Error(),
		)
		return
	}

	if !validateCreateServerAuthConfig(plan.Auth, &resp.Diagnostics) {
		return
	}

	jwtAuthData, jwtDiags := buildCreateServerJWTAuthData(ctx, plan.Auth)
	resp.Diagnostics.Append(jwtDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := swaclient.PostServerJSONRequestBody{
		Name: plan.Name.ValueString(),
		Authentication: swaclient.CreateServerAuthentication{
			Type: swaclient.CreateServerAuthenticationType(plan.Auth.Type.ValueString()),
			Data: swaclient.CreateServerAuthentication_Data{},
		},
	}

	if err := createReq.Authentication.Data.FromCreateServerJWTAuthenticationData(jwtAuthData); err != nil {
		resp.Diagnostics.AddError("Error setting auth data", err.Error())
		return
	}

	params := &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}

	result, err := r.client.PostServerWithResponse(ctx, trustDomainName, serverGroupName, params, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating server", err.Error())
		return
	}

	if result.StatusCode() != http.StatusCreated {
		summary, detail := apiStatusError("creating server", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON201 == nil {
		resp.Diagnostics.AddError("Error creating server", "No response body")
		return
	}

	plan.ID = types.StringValue(fmt.Sprintf("%s/%s/%s", trustDomainName, serverGroupName, result.ApplicationxSecretsmgrV2JSON201.Name))
	plan.AuthnID = types.StringValue(result.ApplicationxSecretsmgrV2JSON201.AuthnId)

	serverAuth, err := serverAuthFromCreateResponse(result.ApplicationxSecretsmgrV2JSON201.Authentication)
	if err != nil {
		resp.Diagnostics.AddError("Error creating server", err.Error())
		return
	}
	if serverAuth != nil {
		if err := syncServerAuthFromResponse(ctx, &plan, serverAuth); err != nil {
			resp.Diagnostics.AddError("Error creating server", err.Error())
			return
		}
	}

	tflog.Trace(ctx, "created server resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *ServerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var state ServerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parts, err := splitSWAID(state.ID.ValueString(), 3, "trust_domain_name/server_group_name/server_name")
	if err != nil {
		resp.Diagnostics.AddError("Invalid server ID", err.Error())
		return
	}
	trustDomainName, serverGroupName, serverName := parts[0], parts[1], parts[2]

	params := &swaclient.GetServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}
	result, err := r.client.GetServerWithResponse(ctx, trustDomainName, serverGroupName, serverName, params)
	if err != nil {
		resp.Diagnostics.AddError("Error reading server", err.Error())
		return
	}

	if result.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if result.StatusCode() != http.StatusOK {
		summary, detail := apiStatusError("reading server", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	if result.ApplicationxSecretsmgrV2JSON200 == nil {
		resp.Diagnostics.AddError("Error reading server", "No response body")
		return
	}

	serverResp := result.ApplicationxSecretsmgrV2JSON200
	if serverResp.ServerGroupName != nil {
		serverGroupName = *serverResp.ServerGroupName
	}

	state.ID = types.StringValue(fmt.Sprintf("%s/%s/%s", trustDomainName, serverGroupName, serverResp.Name))
	state.Name = types.StringValue(serverResp.Name)
	state.ServerGroupID = types.StringValue(fmt.Sprintf("%s/%s", trustDomainName, serverGroupName))
	if serverResp.AuthnId != nil {
		state.AuthnID = types.StringValue(*serverResp.AuthnId)
	} else {
		state.AuthnID = types.StringNull()
	}

	if err := syncServerAuthFromResponse(ctx, &state, serverResp.Authentication); err != nil {
		resp.Diagnostics.AddError("Error reading server", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *ServerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"Servers cannot be updated. Delete and recreate the resource instead.",
	)
}

func (r *ServerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	var state ServerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parts, err := splitSWAID(state.ID.ValueString(), 3, "trust_domain_name/server_group_name/server_name")
	if err != nil {
		resp.Diagnostics.AddError("Invalid server ID", err.Error())
		return
	}
	trustDomainName, serverGroupName, serverName := parts[0], parts[1], parts[2]

	params := &swaclient.DeleteServerParams{
		Accept: swaclient.ApplicationxSecretsmgrV2Json,
	}

	result, err := r.client.DeleteServerWithResponse(ctx, trustDomainName, serverGroupName, serverName, params)
	if err != nil {
		resp.Diagnostics.AddError("Error deleting server", err.Error())
		return
	}

	if result.StatusCode() != http.StatusNoContent && result.StatusCode() != http.StatusNotFound {
		summary, detail := apiStatusError("deleting server", result.StatusCode(), result.Body)
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	tflog.Trace(ctx, "deleted server resource")
}

func (r *ServerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts, err := splitSWAID(req.ID, 3, "trust_domain_name/server_group_name/server_name")
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", err.Error())
		return
	}
	trustDomainName, serverGroupName, serverName := parts[0], parts[1], parts[2]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), serverName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("server_group_id"), fmt.Sprintf("%s/%s", trustDomainName, serverGroupName))...)
}
