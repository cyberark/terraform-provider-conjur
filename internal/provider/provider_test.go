package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

var (
	providerApiConfig   = testProviderAPIConfigData()
	providerIAMConfig   = testProviderIAMConfigData()
	providerAzureConfig = testProviderAzureConfigData()
	providerGCPConfig   = testProviderGCPConfigData()
	providerJWTConfig   = testProviderJWTConfigData()
)

var (
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"conjur": providerserver.NewProtocol6WithError(New("test")()),
	}
)

func TestProviderResourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaRequest := fwprovider.SchemaRequest{}
	schemaResponse := &fwprovider.SchemaResponse{}

	// Instantiate the provider.Provider and call its Schema method
	New("test")().Schema(ctx, schemaRequest, schemaResponse)

	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema method diagnostics: %+v", schemaResponse.Diagnostics)
	}

	// Validate the schema
	diagnostics := schemaResponse.Schema.ValidateImplementation(ctx)

	if diagnostics.HasError() {
		t.Fatalf("Schema validation diagnostics: %+v", diagnostics)
	}
}

func testProviderAPIConfigData() string {
	return fmt.Sprintf(`
		provider "conjur" {
			appliance_url = %[1]q
			account       = %[2]q
			login         = %[3]q
			api_key       = %[4]q
			ssl_cert      = %[5]q
		}`, os.Getenv("CONJUR_APPLIANCE_URL"), os.Getenv("CONJUR_ACCOUNT"), os.Getenv("CONJUR_AUTHN_LOGIN"), os.Getenv("CONJUR_AUTHN_API_KEY"), os.Getenv("CONJUR_CERT_FILE"))
}

func testProviderIAMConfigData() string {
	return fmt.Sprintf(`
        provider "conjur" {
            authn_type    = %[1]q
			appliance_url = %[2]q
			account       = %[3]q
			service_id    = %[4]q
			host_id       = %[5]q
			ssl_cert      = %[6]q
        }`, "aws", os.Getenv("CONJUR_APPLIANCE_URL"), os.Getenv("CONJUR_ACCOUNT"), os.Getenv("TF_IAM_SERVICE_ID"), os.Getenv("TF_IAM_HOST_ID"), os.Getenv("CONJUR_CERT_FILE"))
}

func testProviderAzureConfigData() string {
	return fmt.Sprintf(`
        provider "conjur" {
            authn_type    = %[1]q
			appliance_url = %[2]q
			account       = %[3]q
			service_id    = %[4]q
			host_id       = %[5]q
			ssl_cert      = %[6]q
			client_id     = %[7]q
        }`, "azure", os.Getenv("CONJUR_APPLIANCE_URL"), os.Getenv("CONJUR_ACCOUNT"), os.Getenv("TF_AZ_SERVICE_ID"), os.Getenv("TF_AZ_HOST_ID"), os.Getenv("CONJUR_CERT_FILE"), os.Getenv("TF_CLIENT_ID"))

}

func testProviderGCPConfigData() string {
	gcpToken := os.Getenv("GCP_TOKEN")
	if gcpToken == "" {
		return fmt.Sprintf(`
			provider "conjur" {
				authn_type    = %[1]q
				appliance_url = %[2]q
				account       = %[3]q
				login         = %[4]q
				ssl_cert      = %[5]q
			}`, "gcp", os.Getenv("CONJUR_APPLIANCE_URL"), os.Getenv("CONJUR_ACCOUNT"), os.Getenv("CONJUR_AUTHN_LOGIN"), os.Getenv("CONJUR_CERT_FILE"))
	}

	return fmt.Sprintf(`
		provider "conjur" {
			authn_type    = %[1]q
			appliance_url = %[2]q
			account       = %[3]q
			ssl_cert      = %[4]q
		}`, "gcp", os.Getenv("CONJUR_APPLIANCE_URL"), os.Getenv("CONJUR_ACCOUNT"), os.Getenv("CONJUR_CERT_FILE"))
}

func testProviderJWTConfigData() string {
	return fmt.Sprintf(`
        provider "conjur" {
            authn_type    = %[1]q
			appliance_url = %[2]q
			account       = %[3]q
			service_id    = %[4]q
			host_id       = %[5]q
			ssl_cert      = %[6]q
			authn_jwt_token = %[7]q
        }`, "jwt", os.Getenv("TF_CONJUR_APPLIANCE_URL"), os.Getenv("TF_CONJUR_ACCOUNT"), os.Getenv("TF_JWT_SERVICE_ID"), os.Getenv("TF_JWT_HOST_ID"), os.Getenv("TF_CONJUR_CERT_FILE"), os.Getenv("JWT_TOKEN"))
}

func TestProvider_InvalidAuthnType(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
					provider "conjur" {
						appliance_url = "https://example.com"
						account       = "dev"
						login         = "host/invalid"
						api_key       = "dummykey"
						authn_type    = "foobar"
					}

					data "conjur_secret" "dummy" {
						name = "some/secret"
					}
				`,
				ExpectError: regexp.MustCompile(`Invalid Authn Type`),
			},
		},
	})
}

func TestProvider_MissingAttributes_Azure(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
					provider "conjur" {
						appliance_url = "https://example.com"
						account       = "dev"
						authn_type    = "azure"
						service_id    = "azure-service"
					}

					data "conjur_secret" "dummy" {
						name = "some/secret"
					}
				`,
				ExpectError: regexp.MustCompile(`Missing azure attribute: host_id`),
			},
		},
	})
}

func TestResolveAuthnJWT(t *testing.T) {
	tests := []struct {
		name      string
		authnJWT  types.String
		envToken  string
		wantOk    bool
		wantToken string
	}{
		{
			name:      "token from config",
			authnJWT:  types.StringValue("config-token"),
			envToken:  "",
			wantOk:    true,
			wantToken: "config-token",
		},
		{
			name:      "token from env when config empty",
			authnJWT:  types.StringValue(""),
			envToken:  "env-token",
			wantOk:    true,
			wantToken: "env-token",
		},
		{
			name:      "token from env when config unknown",
			authnJWT:  types.StringUnknown(),
			envToken:  "env-token",
			wantOk:    true,
			wantToken: "env-token",
		},
		{
			name:      "returns false when both empty",
			authnJWT:  types.StringValue(""),
			envToken:  "",
			wantOk:    false,
			wantToken: "",
		},
		{
			name:      "returns false when unknown and env empty",
			authnJWT:  types.StringUnknown(),
			envToken:  "",
			wantOk:    false,
			wantToken: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envToken != "" {
				t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", tt.envToken)
			} else {
				t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", "")
			}
			got, ok := resolveAuthnJWT(tt.authnJWT)
			if ok != tt.wantOk {
				t.Errorf("resolveAuthnJWT() ok = %v, want %v", ok, tt.wantOk)
			}
			if ok && got.ValueString() != tt.wantToken {
				t.Errorf("resolveAuthnJWT() token = %q, want %q", got.ValueString(), tt.wantToken)
			}
		})
	}
}

func TestMayUseStoredCredentials(t *testing.T) {
	// Env vars that influence the decision. Each test starts with all of them
	// cleared and sets only the ones it cares about.
	credentialEnvVars := []string{
		"CONJUR_AUTHN_TOKEN_FILE",
		"CONJUR_AUTHN_TOKEN",
		"CONJUR_AUTHN_LOGIN",
		"CONJUR_AUTHN_API_KEY",
	}

	tests := []struct {
		name string
		data providerModel
		env  map[string]string
		want bool
	}{
		{
			name: "empty authn_type and no credentials falls back to cache",
			data: providerModel{},
			want: true,
		},
		{
			name: "api authn_type and no credentials falls back to cache",
			data: providerModel{AuthnType: types.StringValue("api")},
			want: true,
		},
		{
			name: "non-api authn_type never uses cache",
			data: providerModel{AuthnType: types.StringValue("jwt")},
			want: false,
		},
		{
			name: "azure authn_type never uses cache",
			data: providerModel{AuthnType: types.StringValue("azure")},
			want: false,
		},
		{
			name: "login and api_key set in config",
			data: providerModel{
				Login:  types.StringValue("host/some"),
				APIKey: types.StringValue("secret"),
			},
			want: false,
		},
		{
			name: "only login set in config still falls back to cache",
			data: providerModel{Login: types.StringValue("host/some")},
			want: true,
		},
		{
			name: "only api_key set in config still falls back to cache",
			data: providerModel{APIKey: types.StringValue("secret")},
			want: true,
		},
		{
			name: "CONJUR_AUTHN_TOKEN_FILE set",
			data: providerModel{},
			env:  map[string]string{"CONJUR_AUTHN_TOKEN_FILE": "/tmp/token"},
			want: false,
		},
		{
			name: "CONJUR_AUTHN_TOKEN set",
			data: providerModel{},
			env:  map[string]string{"CONJUR_AUTHN_TOKEN": "token-content"},
			want: false,
		},
		{
			name: "CONJUR_AUTHN_LOGIN and CONJUR_AUTHN_API_KEY set",
			data: providerModel{},
			env: map[string]string{
				"CONJUR_AUTHN_LOGIN":   "host/some",
				"CONJUR_AUTHN_API_KEY": "secret",
			},
			want: false,
		},
		{
			name: "only CONJUR_AUTHN_LOGIN set still falls back to cache",
			data: providerModel{},
			env:  map[string]string{"CONJUR_AUTHN_LOGIN": "host/some"},
			want: true,
		},
		{
			name: "only CONJUR_AUTHN_API_KEY set still falls back to cache",
			data: providerModel{},
			env:  map[string]string{"CONJUR_AUTHN_API_KEY": "secret"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range credentialEnvVars {
				t.Setenv(name, "")
			}
			for name, value := range tt.env {
				t.Setenv(name, value)
			}

			if got := mayUseStoredCredentials(&tt.data); got != tt.want {
				t.Errorf("mayUseStoredCredentials() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateAPIKeyClient_PinsStandardAuthnType(t *testing.T) {
	// conjur-api-go falls back to credentials cached on the machine (e.g. by
	// `conjur login`) when the config's AuthnType is left blank. createAPIKeyClient
	// must pin the standard authn type so an explicit login/api_key is honored and
	// the cached-credentials fallback is not triggered unexpectedly.
	p := &providerImpl{}

	baseConfig := func() *conjurapi.Config {
		return &conjurapi.Config{
			ApplianceURL: "https://example.com",
			Account:      "dev",
			Environment:  conjurapi.EnvironmentSaaS,
		}
	}

	t.Run("with explicit login and api_key", func(t *testing.T) {
		config := baseConfig()
		data := &providerModel{
			Login:  types.StringValue("host/test"),
			APIKey: types.StringValue("secret-key"),
		}

		client, err := p.createAPIKeyClient(config, data)
		if err != nil {
			t.Fatalf("createAPIKeyClient returned error: %v", err)
		}
		if got := client.GetConfig().AuthnType; got != conjurapi.AuthnTypeStandard {
			t.Errorf("AuthnType = %q, want %q", got, conjurapi.AuthnTypeStandard)
		}
	})

	t.Run("without login and api_key", func(t *testing.T) {
		// Ensure no env credentials leak in from the host running the tests.
		t.Setenv("CONJUR_AUTHN_TOKEN_FILE", "")
		t.Setenv("CONJUR_AUTHN_TOKEN", "")
		t.Setenv("CONJUR_AUTHN_LOGIN", "host/test")
		t.Setenv("CONJUR_AUTHN_API_KEY", "secret-key")

		config := baseConfig()
		client, err := p.createAPIKeyClient(config, &providerModel{})
		if err != nil {
			t.Fatalf("createAPIKeyClient returned error: %v", err)
		}
		if got := client.GetConfig().AuthnType; got != conjurapi.AuthnTypeStandard {
			t.Errorf("AuthnType = %q, want %q", got, conjurapi.AuthnTypeStandard)
		}
	})
}

func TestCreateAPIKeyClient_PreservesStoredCredentialAuthnType(t *testing.T) {
	// When no inline login/api_key is supplied, createAPIKeyClient falls back to
	// credentials cached by `conjur login`. For stored-credential authn types such
	// as "cloud" (SaaS/Secrets Manager) and "oidc", it must NOT overwrite the
	// AuthnType loaded from ~/.conjurrc: doing so routes the credential lookup to
	// the generic authn store and misses the cached SaaS/OIDC credentials,
	// producing a spurious "No valid credentials found" error.
	p := &providerImpl{}

	baseConfig := func(authnType string) *conjurapi.Config {
		return &conjurapi.Config{
			ApplianceURL: "https://example.com",
			Account:      "dev",
			Environment:  conjurapi.EnvironmentSaaS,
			AuthnType:    authnType,
		}
	}

	// Avoid leaking env credentials that would change the fallback path.
	for _, name := range []string{
		"CONJUR_AUTHN_TOKEN_FILE",
		"CONJUR_AUTHN_TOKEN",
		"CONJUR_AUTHN_LOGIN",
		"CONJUR_AUTHN_API_KEY",
	} {
		t.Setenv(name, "")
	}

	for _, authnType := range []string{conjurapi.AuthnTypeCloud, "oidc", "ldap"} {
		t.Run(authnType+" is preserved without inline credentials", func(t *testing.T) {
			config := baseConfig(authnType)
			// The client build may fail because no real cached credentials exist
			// in the test environment, but the mutation on config we care about
			// happens before that. Assert on config, not the returned client.
			_, _ = p.createAPIKeyClient(config, &providerModel{})
			if config.AuthnType != authnType {
				t.Errorf("AuthnType = %q, want %q (stored-credential type must be preserved)", config.AuthnType, authnType)
			}
		})
	}

	t.Run("blank authn_type is pinned to standard without inline credentials", func(t *testing.T) {
		config := baseConfig("")
		_, _ = p.createAPIKeyClient(config, &providerModel{})
		if config.AuthnType != conjurapi.AuthnTypeStandard {
			t.Errorf("AuthnType = %q, want %q", config.AuthnType, conjurapi.AuthnTypeStandard)
		}
	})
}

func TestValidateAttributes_JWT(t *testing.T) {
	t.Run("passes when required attributes set", func(t *testing.T) {
		attributes := map[string]types.String{
			"appliance_url": types.StringValue("https://example.com"),
			"service_id":    types.StringValue("jwt-svc"),
		}
		resp := &provider.ValidateConfigResponse{}
		validateAttributes(attributes, "jwt", resp)

		if resp.Diagnostics.HasError() {
			t.Errorf("validateAttributes should not error when appliance_url and service_id are set; got: %v", resp.Diagnostics)
		}
	})

	t.Run("errors when service_id missing", func(t *testing.T) {
		attributes := map[string]types.String{
			"appliance_url": types.StringValue("https://example.com"),
			"service_id":    types.StringValue(""),
		}
		resp := &provider.ValidateConfigResponse{}
		validateAttributes(attributes, "jwt", resp)

		if !resp.Diagnostics.HasError() {
			t.Fatal("validateAttributes should error when service_id is missing")
		}
	})
}

// getProviderTestSchema returns the provider schema for building test configs.
func getProviderTestSchema() schema.Schema {
	p := &providerImpl{}
	var schemaResp provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}

// newValidateConfigRequest builds a ValidateConfigRequest whose config reflects
// the supplied providerModel, so ValidateConfig can be exercised end-to-end.
func newValidateConfigRequest(data providerModel) provider.ValidateConfigRequest {
	str := func(v types.String) tftypes.Value {
		if v.IsNull() {
			return tftypes.NewValue(tftypes.String, nil)
		}
		return tftypes.NewValue(tftypes.String, v.ValueString())
	}

	configVal := tftypes.NewValue(
		tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"authn_type":      tftypes.String,
				"appliance_url":   tftypes.String,
				"account":         tftypes.String,
				"login":           tftypes.String,
				"api_key":         tftypes.String,
				"service_id":      tftypes.String,
				"client_id":       tftypes.String,
				"host_id":         tftypes.String,
				"ssl_cert":        tftypes.String,
				"ssl_cert_path":   tftypes.String,
				"authn_jwt_token": tftypes.String,
			},
		},
		map[string]tftypes.Value{
			"authn_type":      str(data.AuthnType),
			"appliance_url":   str(data.ApplianceUrl),
			"account":         str(data.Account),
			"login":           str(data.Login),
			"api_key":         str(data.APIKey),
			"service_id":      str(data.ServiceID),
			"client_id":       str(data.ClientID),
			"host_id":         str(data.HostID),
			"ssl_cert":        str(data.SSLCert),
			"ssl_cert_path":   str(data.SSLCertPath),
			"authn_jwt_token": str(data.AuthnJWT),
		},
	)

	return provider.ValidateConfigRequest{
		Config: tfsdk.Config{
			Raw:    configVal,
			Schema: getProviderTestSchema(),
		},
	}
}

func TestValidateConfig_APIAuthnTypeWithoutCredentials(t *testing.T) {
	// authn_type = "api" without a resolvable login/api_key silently falls back
	// to credentials cached by `conjur login`. ValidateConfig must surface that
	// decoupling as a warning (not an error) so the fallback stays usable.
	credentialEnvVars := []string{
		"CONJUR_AUTHN_TOKEN_FILE",
		"CONJUR_AUTHN_TOKEN",
		"CONJUR_AUTHN_LOGIN",
		"CONJUR_AUTHN_API_KEY",
	}

	const warnSummary = "authn_type = \"api\" but no API key provided"

	hasWarning := func(resp *provider.ValidateConfigResponse) bool {
		for _, d := range resp.Diagnostics.Warnings() {
			if d.Summary() == warnSummary {
				return true
			}
		}
		return false
	}

	p := &providerImpl{}
	ctx := context.Background()

	tests := []struct {
		name string
		data providerModel
		env  map[string]string
		want bool
	}{
		{
			name: "api with no credentials warns",
			data: providerModel{
				AuthnType:    types.StringValue("api"),
				ApplianceUrl: types.StringValue("https://example.com"),
			},
			want: true,
		},
		{
			name: "api with inline login and api_key does not warn",
			data: providerModel{
				AuthnType:    types.StringValue("api"),
				ApplianceUrl: types.StringValue("https://example.com"),
				Login:        types.StringValue("host/some"),
				APIKey:       types.StringValue("secret"),
			},
			want: false,
		},
		{
			name: "api with env credentials does not warn",
			data: providerModel{
				AuthnType:    types.StringValue("api"),
				ApplianceUrl: types.StringValue("https://example.com"),
			},
			env: map[string]string{
				"CONJUR_AUTHN_LOGIN":   "host/some",
				"CONJUR_AUTHN_API_KEY": "secret",
			},
			want: false,
		},
		{
			name: "empty authn_type does not warn",
			data: providerModel{
				ApplianceUrl: types.StringValue("https://example.com"),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range credentialEnvVars {
				t.Setenv(name, "")
			}
			for name, value := range tt.env {
				t.Setenv(name, value)
			}

			resp := &provider.ValidateConfigResponse{}
			p.ValidateConfig(ctx, newValidateConfigRequest(tt.data), resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("ValidateConfig returned errors: %v", resp.Diagnostics.Errors())
			}
			if got := hasWarning(resp); got != tt.want {
				t.Errorf("cached-credentials warning present = %v, want %v (diags: %v)", got, tt.want, resp.Diagnostics)
			}
		})
	}
}
