package provider

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

var (
	_ provider.Provider                   = &conjurProvider{}
	_ provider.ProviderWithValidateConfig = &conjurProvider{}
)

type conjurProvider struct {
	version string
}

// conjurProviderModel describes the provider data model.
type conjurProviderModel struct {
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
func (p *conjurProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "conjur"
	resp.Version = p.version
}

func (p *conjurProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetch secrets and load, replace, update, fetch policy into Conjur Vault",
		Attributes: map[string]schema.Attribute{
			"authn_type": schema.StringAttribute{
				Optional:    true,
				Description: "Conjur Authentication Type",
			},
			"appliance_url": schema.StringAttribute{
				Optional:    true,
				Description: "Conjur endpoint URL",
			},
			"account": schema.StringAttribute{
				Optional:    true,
				Description: "Conjur account",
			},
			"login": schema.StringAttribute{
				Optional:    true,
				Description: "Conjur login",
			},
			"host_id": schema.StringAttribute{
				Optional:    true,
				Description: "Conjur host id",
			},
			"service_id": schema.StringAttribute{
				Optional:    true,
				Description: "Conjur service id",
			},
			"client_id": schema.StringAttribute{
				Optional:    true,
				Description: "Azure client id for user assigned managed identity",
			},
			"api_key": schema.StringAttribute{
				Optional:    true,
				Description: "Conjur API key",
			},
			"ssl_cert": schema.StringAttribute{
				Optional:    true,
				Description: "Content of Conjur public SSL certificate",
			},
			"ssl_cert_path": schema.StringAttribute{
				Optional:    true,
				Description: "Path to Conjur public SSL certificate",
			},
			"authn_jwt_token": schema.StringAttribute{
				Optional:    true,
				Description: "Authn JWT Token",
			},
		},
	}
}

func (p *conjurProvider) ValidateConfig(ctx context.Context, req provider.ValidateConfigRequest, resp *provider.ValidateConfigResponse) {
	var data conjurProviderModel

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
		"appliance_url":   data.ApplianceUrl,
		"service_id":      data.ServiceID,
		"authn_jwt_token": data.AuthnJWT,
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

func (p *conjurProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data conjurProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, err := p.buildConjurConfig(&data)
	if err != nil {
		resp.Diagnostics.AddError("Unable to load config", err.Error())
		return
	}

	client, err := p.createConjurClient(config, &data)
	if err != nil {
		resp.Diagnostics.AddError("Client initialization failed", err.Error())
		return
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *conjurProvider) buildConjurConfig(data *conjurProviderModel) (*conjurapi.Config, error) {
	config, err := conjurapi.LoadConfig()
	if err != nil {
		return nil, err
	}

	config.SetIntegrationName("TerraformSecretsManager")
	config.SetIntegrationType("cybr-secretsmanager-go-sdk")
	config.SetIntegrationVersion("0.6.12")
	config.SetVendorName("HashiCorp")

	// Apply configuration overrides if specified in the Terraform provider block
	p.applyConfigOverrides(&config, data)

	return &config, nil
}

func (p *conjurProvider) applyConfigOverrides(config *conjurapi.Config, data *conjurProviderModel) {
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

func (p *conjurProvider) createConjurClient(config *conjurapi.Config, data *conjurProviderModel) (*conjurapi.Client, error) {
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

func (p *conjurProvider) createJWTClient(config *conjurapi.Config, data *conjurProviderModel) (*conjurapi.Client, error) {
	config.ServiceID = data.ServiceID.ValueString()
	config.JWTHostID = data.HostID.ValueString()
	config.AuthnType = data.AuthnType.ValueString()
	config.JWTContent = data.AuthnJWT.ValueString()

	return conjurapi.NewClientFromJwt(*config)
}

func (p *conjurProvider) createGCPClient(config *conjurapi.Config, data *conjurProviderModel) (*conjurapi.Client, error) {
	config.ServiceID = data.ServiceID.ValueString()
	config.AuthnType = "gcp"
	config.JWTHostID = strings.TrimPrefix(data.HostID.ValueString(), "host/")

	// The below is sort-of a hack to test this in CI, where our GCP runners apparently don't
	// have docker, and therefore can not use the GCP metadata service to fetch tokens
	if gcpToken := os.Getenv("GCP_TOKEN"); gcpToken != "" {
		config.JWTContent = gcpToken
		return conjurapi.NewClientFromJwt(*config)
	}

	return conjurapi.NewClientFromStoredGCPConfig(*config)
}

func (p *conjurProvider) createAzureClient(config *conjurapi.Config, data *conjurProviderModel) (*conjurapi.Client, error) {
	config.ServiceID = data.ServiceID.ValueString()
	config.AuthnType = "azure"
	config.JWTHostID = strings.TrimPrefix(data.HostID.ValueString(), "host/")
	if !data.ClientID.IsNull() && !data.ClientID.IsUnknown() {
		config.AzureClientID = data.ClientID.ValueString()
	}

	return conjurapi.NewClientFromAzureCredentials(*config)
}

func (p *conjurProvider) createIAMClient(config *conjurapi.Config, data *conjurProviderModel) (*conjurapi.Client, error) {
	config.ServiceID = data.ServiceID.ValueString()
	config.AuthnType = "iam"
	config.JWTHostID = strings.TrimPrefix(data.HostID.ValueString(), "host/")

	return conjurapi.NewClientFromAWSCredentials(*config)
}

func (p *conjurProvider) createAPIKeyClient(config *conjurapi.Config, data *conjurProviderModel) (*conjurapi.Client, error) {
	login := data.Login.ValueString()
	apiKey := data.APIKey.ValueString()

	if login != "" && apiKey != "" {
		return conjurapi.NewClientFromKey(*config, authn.LoginPair{
			Login:  login,
			APIKey: apiKey,
		})
	}

	return conjurapi.NewClientFromEnvironment(*config)
}

func (p *conjurProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSecretDataSource,
	}
}

// Resources define the resources implemented in the provider.
func (p *conjurProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewConjurAuthenticatorResource,
		NewConjurHostResource,
		NewConjurGroupResource,
		NewConjurPermissionResource,
	}
}

// New creates a new provider instance.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &conjurProvider{
			version: version,
		}
	}
}
