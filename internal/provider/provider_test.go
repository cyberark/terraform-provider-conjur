package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
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

func TestProvider_InvalidJWTToken(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
					provider "conjur" {
						appliance_url    = "https://example.com"
						account          = "dev"
						authn_type       = "jwt"
						service_id       = "jwt-svc"
						host_id          = "host/test"
						authn_jwt_token  = ""
					}

					data "conjur_secret" "dummy" {
						name = "some/secret"
					}
				`,
				ExpectError: regexp.MustCompile(`Missing jwt attribute: authn_jwt_token`),
			},
		},
	})
}
