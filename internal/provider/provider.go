package provider

import (
	"context"
	"fmt"
	"net/http"
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

	conjurClient, err := p.createClient(config, &data)
	if err != nil {
		resp.Diagnostics.AddError("Client initialization failed", err.Error())
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
		config.ApplianceURL = url
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

	config.CredentialStorage = conjurapi.CredentialStorageNone
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
		return conjurapi.NewClientFromKey(*config, authn.LoginPair{
			Login:  login,
			APIKey: apiKey,
		}, telemetryData)
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
		//NewTrustDomainResource,
		//NewServerGroupResource,
		//NewServerResource,
		//NewNodeGroupResource,
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
