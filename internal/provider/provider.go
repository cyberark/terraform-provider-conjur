package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

// providerClients holds both the Conjur API client and the SWA client.
// It is passed as ProviderData to all resources and data sources.
type providerClients struct {
	conjurClient api.ClientV2
	swaClient    swaclient.ClientWithResponsesInterface
}

// AuthTransport is an http.RoundTripper that delegates to a conjur-api-go
// Client, giving the SWA HTTP client automatic token refresh for all authn types.
type AuthTransport struct {
	ConjurClient *conjurapi.Client
}

func (t *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.ConjurClient.SubmitRequest(req)
}

// IntegrationVersion is injected at build time via ldflags.
// Defaults for local builds so `go build` still works.
var IntegrationVersion = "0.0.1"

var telemetryData = conjurapi.NewTelemetry("Terraform Provider", "idira-secretsmanager", IntegrationVersion, "Idira", "")

var (
	_ provider.Provider                       = &providerImpl{}
	_ provider.ProviderWithValidateConfig     = &providerImpl{}
	_ provider.ProviderWithEphemeralResources = &providerImpl{}
)

type providerImpl struct {
	version string
	client  api.ClientV2
}

// providerModel describes the provider data model.
type providerModel struct {
	AuthnType    types.String `tfsdk:"authn_type"`
	ApplianceUrl types.String `tfsdk:"appliance_url"`
	Account      types.String `tfsdk:"account"`
	Login        types.String `tfsdk:"login"`
	APIKey       types.String `tfsdk:"api_key"`
	ServiceID    types.String `tfsdk:"service_id"`
	ClientID     types.String `tfsdk:"client_id"`
	HostID       types.String `tfsdk:"host_id"`
	SSLCert      types.String `tfsdk:"ssl_cert"`
	SSLCertPath  types.String `tfsdk:"ssl_cert_path"`
	AuthnJWT     types.String `tfsdk:"authn_jwt_token"`
}

// Metadata returns the provider type name.
func (p *providerImpl) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "conjur"
	resp.Version = p.version
}

func (p *providerImpl) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetch secrets and manage CyberArk Secrets Manager resources.",
		Attributes: map[string]schema.Attribute{
			"authn_type": schema.StringAttribute{
				Optional:    true,
				Description: "CyberArk Secrets Manager Authentication Type",
			},
			"appliance_url": schema.StringAttribute{
				Optional:    true,
				Description: "CyberArk Secrets Manager endpoint URL",
			},
			"account": schema.StringAttribute{
				Optional:    true,
				Description: "CyberArk Secrets Manager account",
			},
			"login": schema.StringAttribute{
				Optional:    true,
				Description: "CyberArk Secrets Manager login",
			},
			"host_id": schema.StringAttribute{
				Optional:    true,
				Description: "CyberArk Secrets Manager host ID",
			},
			"service_id": schema.StringAttribute{
				Optional:    true,
				Description: "CyberArk Secrets Manager service ID",
			},
			"client_id": schema.StringAttribute{
				Optional:    true,
				Description: "Azure client ID for user assigned managed identity",
			},
			"api_key": schema.StringAttribute{
				Optional:    true,
				Description: "CyberArk Secrets Manager API key",
				Sensitive:   true,
			},
			"ssl_cert": schema.StringAttribute{
				Optional:    true,
				Description: "Content of CyberArk Secrets Manager public SSL certificate",
			},
			"ssl_cert_path": schema.StringAttribute{
				Optional:    true,
				Description: "Path to CyberArk Secrets Manager public SSL certificate",
			},
			"authn_jwt_token": schema.StringAttribute{
				Optional:    true,
				Description: "Authn JWT Token",
				Sensitive:   true,
			},
		},
	}
}

func (p *providerImpl) ValidateConfig(ctx context.Context, req provider.ValidateConfigRequest, resp *provider.ValidateConfigResponse) {
	var data providerModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate Authentication Types
	validAuthnTypes := []string{"api", "aws", "azure", "gcp", "jwt"}
	if data.AuthnType.ValueString() != "" {
		valid := false
		for _, method := range validAuthnTypes {
			if data.AuthnType.ValueString() == method {
				valid = true
				break
			}
		}

		if !valid {
			resp.Diagnostics.AddError("Invalid Authn Type",
				fmt.Sprintf("Invalid Authn Type: %s. Valid methods are: %v", data.AuthnType.ValueString(), validAuthnTypes))
			return
		}
	}

	authApiAttributes := map[string]types.String{
		"appliance_url": data.ApplianceUrl,
	}

	// Validate IAM attributes
	authIamAzureAttributes := map[string]types.String{
		"appliance_url": data.ApplianceUrl,
		"host_id":       data.HostID,
		"service_id":    data.ServiceID,
	}

	authGcpAttributes := map[string]types.String{
		"appliance_url": data.ApplianceUrl,
	}

	authnJWTAttributes := map[string]types.String{
		"appliance_url": data.ApplianceUrl,
		"service_id":    data.ServiceID,
		// authn_jwt_token omitted - may come from TFC_WORKLOAD_IDENTITY_TOKEN env var
	}

	switch data.AuthnType.ValueString() {
	case "aws", "azure":
		validateAttributes(authIamAzureAttributes, data.AuthnType.ValueString(), resp)
	case "gcp":
		validateAttributes(authGcpAttributes, "gcp", resp)
	case "jwt":
		validateAttributes(authnJWTAttributes, "jwt", resp)
	case "api":
		validateAttributes(authApiAttributes, "api", resp)
		// authn_type is explicitly "api" but createAPIKeyClient only performs a
		// true API-key exchange when a login/api_key is resolvable (from config
		// or the CONJUR_AUTHN_* env vars). Otherwise it falls back to the
		// credentials cached by `conjur login`, so the explicit "api" type does
		// not actually force API-key auth. Warn so the mismatch is visible.
		if mayUseStoredCredentials(&data) {
			resp.Diagnostics.AddWarning(
				"authn_type = \"api\" but no API key provided",
				"authn_type is set to \"api\" but no login/api_key was found in the provider config or CONJUR_AUTHN_* env vars. "+
					"The provider will fall back to credentials cached by `conjur login`. Set login+api_key to force API-key auth.",
			)
		}
	case "":
		// No authn_type specified – fallback to API validation
		validateAttributes(authApiAttributes, "api", resp)
	}
}

func validateAttributes(attributes map[string]types.String, label string, resp *provider.ValidateConfigResponse) {
	anySet := false
	for _, attr := range attributes {
		if attr.ValueString() != "" {
			anySet = true
			break
		}
	}

	if anySet {
		for name, attr := range attributes {
			if attr.ValueString() == "" {
				resp.Diagnostics.AddError(
					fmt.Sprintf("Missing %s Attribute", label),
					fmt.Sprintf("Missing %s attribute: %s", label, name),
				)
			}
		}
	}
}

func (p *providerImpl) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.AuthnType.ValueString() == "jwt" {
		if token, ok := resolveAuthnJWT(data.AuthnJWT); !ok {
			// Client will be nil; resources/data sources log when operations are skipped
			return
		} else {
			data.AuthnJWT = token
		}
	}

	config, err := p.buildConfig(&data)
	if err != nil {
		resp.Diagnostics.AddError("Unable to load config", err.Error())
		return
	}

	if mayUseStoredCredentials(&data) {
		resp.Diagnostics.AddWarning(
			"Using cached Secrets Manager credentials",
			"No login information provided, will try using cached Secrets Manager credentials (e.g. by `conjur login`).",
		)
	}

	conjurClient, err := p.createClient(config, &data)
	if err != nil {
		resp.Diagnostics.AddError("Client initialization failed", err.Error())
		return
	}

	// Eagerly obtain an access token so authentication problems surface here,
	// with a clear message, instead of as a confusing per-resource error during
	// the first API call (e.g. "Error reading trust domain: 404 Not Found" when
	// the real cause is an expired session). RefreshToken reuses a valid cached
	// token when one is present (e.g. from `conjur login`) and only contacts the
	// server when a refresh is actually needed, so this does not break the
	// cached-credentials workflow.
	if err := conjurClient.RefreshToken(); err != nil {
		resp.Diagnostics.AddError(
			"Conjur authentication failed",
			fmt.Sprintf(
				"Could not authenticate to CyberArk Secrets Manager at %s: %s\n\n"+
					"Verify your credentials (login/api_key, CONJUR_AUTHN_* environment variables, "+
					"or a session cached by `conjur login`) and that the host is authorized. "+
					"If a `conjur login` session has expired, run `conjur login` again.",
				conjurClient.GetConfig().ApplianceURL, err,
			),
		)
		return
	}

	applianceURL := strings.TrimSuffix(strings.TrimSuffix(conjurClient.GetConfig().ApplianceURL, "/"), "/api")
	swaC, err := swaclient.NewSWAClientWithTransport(applianceURL, &AuthTransport{ConjurClient: conjurClient})
	if err != nil {
		resp.Diagnostics.AddError("SWA client initialization failed", err.Error())
		return
	}

	clients := &providerClients{
		conjurClient: conjurClient.V2(),
		swaClient:    swaC,
	}

	resp.DataSourceData = clients
	resp.ResourceData = clients
	resp.EphemeralResourceData = clients
}

// mayUseStoredCredentials reports whether createAPIKeyClient is likely to fall back
// to conjur-api-go's cached credential storage (e.g. credentials saved by a prior
// `conjur login`) because no login/API key was supplied via the provider config or
// via the CONJUR_AUTHN_LOGIN/CONJUR_AUTHN_API_KEY environment variables. It mirrors
// the precedence documented on conjurapi.NewClientFromEnvironment, which is what
// createAPIKeyClient delegates to in this situation.
func mayUseStoredCredentials(data *providerModel) bool {
	authnType := data.AuthnType.ValueString()
	if authnType != "" && authnType != "api" {
		return false
	}

	if data.Login.ValueString() != "" && data.APIKey.ValueString() != "" {
		return false
	}

	if os.Getenv("CONJUR_AUTHN_TOKEN_FILE") != "" || os.Getenv("CONJUR_AUTHN_TOKEN") != "" {
		return false
	}

	if os.Getenv("CONJUR_AUTHN_LOGIN") != "" && os.Getenv("CONJUR_AUTHN_API_KEY") != "" {
		return false
	}

	return true
}

// resolveAuthnJWT returns the JWT from config or TFC_WORKLOAD_IDENTITY_TOKEN env var.
// ok is false if the token is unknown or could not be resolved (caller should defer auth).
func resolveAuthnJWT(authnJWT types.String) (types.String, bool) {
	token := authnJWT.ValueString()
	if token == "" {
		token = os.Getenv("TFC_WORKLOAD_IDENTITY_TOKEN")
	}
	if token == "" {
		return types.String{}, false
	}
	return types.StringValue(token), true
}

func (p *providerImpl) buildConfig(data *providerModel) (*conjurapi.Config, error) {
	config, err := conjurapi.LoadConfig()
	if err != nil {
		return nil, err
	}

	// Apply configuration overrides if specified in the Terraform provider block
	p.applyConfigOverrides(&config, data)

	return &config, nil
}

func (p *providerImpl) applyConfigOverrides(config *conjurapi.Config, data *providerModel) {
	if url := data.ApplianceUrl.ValueString(); url != "" {
		config.ApplianceURL = canonicalizeApplianceURL(url)
	}

	if account := data.Account.ValueString(); account != "" {
		config.Account = account
	}

	if cert := data.SSLCert.ValueString(); cert != "" {
		config.SSLCert = cert
	}

	if certPath := data.SSLCertPath.ValueString(); certPath != "" {
		config.SSLCertPath = certPath
	}

	// Reuse credentials cached by `conjur login` but do not persist new ones from
	// Terraform runs. Skip the override when the user set the storage mode via env.
	if os.Getenv("CONJUR_CREDENTIAL_STORAGE_MODE") == "" {
		config.CredentialStorageMode = conjurapi.CredentialStorageModeReadOnly
	}
}

// canonicalizeApplianceURL normalizes a Conjur Cloud appliance URL to always
// include the "/api" path segment, regardless of what the caller supplied.
// `conjur init saas` writes appliance_url with a "/api" suffix to .conjurrc,
// so `conjur login` always caches OIDC tokens under an "/api"-suffixed key
// (conjur-api-go's credential cache key is derived directly from
// ApplianceURL). Without this, a provider block that omits "/api" computes a
// different cache key than the one `conjur login` wrote, and stored
// credentials silently fail to be found. On-prem appliance URLs never use
// this convention, so non-cloud URLs are left untouched.
func canonicalizeApplianceURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || !conjurapi.ConjurCloudRegexp.MatchString(strings.ToLower(parsed.Hostname())) {
		return rawURL
	}

	trimmedPath := strings.TrimRight(parsed.Path, "/")
	if trimmedPath != "" && !strings.EqualFold(trimmedPath, "/api") {
		// Unexpected path shape -- don't guess, leave it as-is.
		return rawURL
	}

	parsed.Path = "/api"
	return parsed.String()
}

func (p *providerImpl) createClient(config *conjurapi.Config, data *providerModel) (*conjurapi.Client, error) {
	authnType := data.AuthnType.ValueString()

	switch authnType {
	case "azure":
		return p.createAzureClient(config, data)
	case "gcp":
		return p.createGCPClient(config, data)
	case "aws", "iam":
		return p.createIAMClient(config, data)
	case "jwt":
		return p.createJWTClient(config, data)
	case "", "api":
		return p.createAPIKeyClient(config, data)
	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", authnType)
	}
}

func (p *providerImpl) createJWTClient(config *conjurapi.Config, data *providerModel) (*conjurapi.Client, error) {
	config.ServiceID = data.ServiceID.ValueString()
	config.JWTHostID = data.HostID.ValueString()
	config.AuthnType = data.AuthnType.ValueString()
	config.JWTContent = data.AuthnJWT.ValueString()

	return conjurapi.NewClientFromJwt(*config, telemetryData)
}

func (p *providerImpl) createGCPClient(config *conjurapi.Config, data *providerModel) (*conjurapi.Client, error) {
	config.ServiceID = data.ServiceID.ValueString()
	config.AuthnType = "gcp"
	config.JWTHostID = strings.TrimPrefix(data.HostID.ValueString(), "host/")

	// The below is sort-of a hack to test this in CI, where our GCP runners apparently don't
	// have docker, and therefore can not use the GCP metadata service to fetch tokens
	if gcpToken := os.Getenv("GCP_TOKEN"); gcpToken != "" {
		config.JWTContent = gcpToken
	}

	return conjurapi.NewClientFromGCPCredentials(*config, "", telemetryData)
}

func (p *providerImpl) createAzureClient(config *conjurapi.Config, data *providerModel) (*conjurapi.Client, error) {
	config.ServiceID = data.ServiceID.ValueString()
	config.AuthnType = "azure"
	config.JWTHostID = strings.TrimPrefix(data.HostID.ValueString(), "host/")
	if !data.ClientID.IsNull() && !data.ClientID.IsUnknown() {
		config.AzureClientID = data.ClientID.ValueString()
	}

	return conjurapi.NewClientFromAzureCredentials(*config, telemetryData)
}

func (p *providerImpl) createIAMClient(config *conjurapi.Config, data *providerModel) (*conjurapi.Client, error) {
	config.ServiceID = data.ServiceID.ValueString()
	config.AuthnType = "iam"
	config.JWTHostID = strings.TrimPrefix(data.HostID.ValueString(), "host/")

	return conjurapi.NewClientFromAWSCredentials(*config, telemetryData)
}

func (p *providerImpl) createAPIKeyClient(config *conjurapi.Config, data *providerModel) (*conjurapi.Client, error) {
	login := data.Login.ValueString()
	apiKey := data.APIKey.ValueString()

	if login != "" && apiKey != "" {
		// Pin the standard authn type so conjur-api-go binds to the API-key
		// authenticator instead of silently falling back to credentials cached
		// on the machine (e.g. by `conjur login`). Without this, an unset
		// CONJUR_AUTHN_TYPE leaves the type blank and conjur-api-go treats
		// stored credentials as a valid source.
		config.AuthnType = conjurapi.AuthnTypeStandard
		return conjurapi.NewClientFromKey(*config, authn.LoginPair{
			Login:  login,
			APIKey: apiKey,
		}, telemetryData)
	}

	// No inline API key was supplied, so we fall back to whatever credentials
	// conjur-api-go can find (env vars or those cached by `conjur login`).
	if config.AuthnType == "" {
		config.AuthnType = conjurapi.AuthnTypeStandard
	}
	return conjurapi.NewClientFromEnvironment(*config, telemetryData)
}

func (p *providerImpl) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSecretDataSource,
		NewCertificateIssueDataSource,
		NewCertificateSignDataSource,
	}
}

// EphemeralResources returns the ephemeral resources implemented in the provider.
func (p *providerImpl) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		NewEphemeralSecretResource,
	}
}

// Resources define the resources implemented in the provider.
func (p *providerImpl) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAuthenticatorResource,
		NewHostResource,
		NewGroupResource,
		NewPermissionResource,
		NewMembershipResource,
		NewSecretResource,
		NewPolicyBranchResource,
		NewTrustDomainResource,
		NewServerGroupResource,
		NewServerResource,
		NewNodeGroupResource,
	}
}

// New creates a new provider instance.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &providerImpl{
			version: version,
		}
	}
}
