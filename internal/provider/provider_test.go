package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
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
