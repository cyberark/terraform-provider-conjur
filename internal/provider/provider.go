package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/terraform-provider-conjur/internal/multi_cloud_access_token"
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
				Required:    true,
				Description: "Conjur endpoint URL",
			},
			"account": schema.StringAttribute{
				Required:    true,
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
		"appliance_url": data.ApplianceUrl,
		"service_id":    data.ServiceID,
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
	var err error
	var token string
	gcpEnvToken := os.Getenv("GCP_TOKEN")
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	conjurConfig, err := conjurapi.LoadConfig()
	if err != nil {
		resp.Diagnostics.AddError("Unable to load config", err.Error())
		return
	}
	conjurConfig.CredentialStorage = conjurapi.CredentialStorageNone

	account := data.Account.ValueString()
	if account == "" {
		account = "conjur"
	}
	conjurConfig.ApplianceURL = data.ApplianceUrl.ValueString()
	conjurConfig.Account = account
	conjurConfig.SSLCert = data.SSLCert.ValueString()
	conjurConfig.SSLCertPath = data.SSLCertPath.ValueString()
	conjurConfig.SetIntegrationName("TerraformSecretsManager")
    conjurConfig.SetIntegrationType("cybr-secretsmanager-go-sdk")
    conjurConfig.SetIntegrationVersion("0.6.12")
    conjurConfig.SetVendorName("HashiCorp")

	var client *conjurapi.Client
	authnType := data.AuthnType.ValueString()
	switch authnType {
	case "aws", "azure", "gcp":
		var tkprovider multi_cloud_access_token.TokenProvider
		switch authnType {
		case "azure":
			tkprovider = &multi_cloud_access_token.AzureTokenProvider{}
		case "gcp":
			if gcpEnvToken == "" {
				tkprovider = &multi_cloud_access_token.GCPTokenProvider{
					Account: account,
					HostID:  data.Login.ValueString(),
				}
		    } else {
				token = gcpEnvToken
			}
		case "aws":
			tkprovider = &multi_cloud_access_token.IAMTokenProvider{}
		}
		if authnType == "aws" {
			conjurConfig.AuthnType = "iam"
		} else {
			conjurConfig.AuthnType = data.AuthnType.ValueString()
		}
		conjurConfig.ServiceID = data.ServiceID.ValueString()
		conjurConfig.JWTHostID = data.HostID.ValueString()
		if gcpEnvToken == "" {
			token, err = tkprovider.Token(data.ClientID.ValueString())
			if err != nil {
				resp.Diagnostics.AddError(
					fmt.Sprintf("Error getting token from %s provider", authnType),
					fmt.Sprintf("Error getting token: %s", err.Error()),
				)
				return
			}
	    }
		conjurConfig.JWTContent = token
		client, err = conjurapi.NewClientFromJwt(conjurConfig)
		token = ""
		if err != nil {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Failed to initialize Conjur client for %s authn-type", authnType),
				fmt.Sprintf("Failed to initialize Conjur client: %s", err.Error()),
			)
			return
		}
	case "jwt":
		conjurConfig.ServiceID = data.ServiceID.ValueString()
		conjurConfig.JWTHostID = data.HostID.ValueString()
		conjurConfig.AuthnType = data.AuthnType.ValueString()
		conjurConfig.JWTContent = data.AuthnJWT.ValueString()
		client, err = conjurapi.NewClientFromJwt(conjurConfig)
		if err != nil {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Failed to initialize Conjur client for %s authn-type", authnType),
				fmt.Sprintf("Failed to initialize Conjur client: %s", err.Error()),
			)
			return
		}
	case "", "api":
		if data.Login.ValueString() != "" && data.APIKey.ValueString() != "" {
			client, err = conjurapi.NewClientFromKey(conjurConfig, authn.LoginPair{
				Login:  data.Login.ValueString(),
				APIKey: data.APIKey.ValueString(),
			})
		} else {
			client, err = conjurapi.NewClientFromEnvironment(conjurConfig)
		}
	}
	if err != nil {
		resp.Diagnostics.AddError("Client initialization failed", err.Error())
		return
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *conjurProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSecretDataSource,
	}
}

// Resources define the resources implemented in the provider.
func (p *conjurProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

// New creates a new provider instance.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &conjurProvider{
			version: version,
		}
	}
}
