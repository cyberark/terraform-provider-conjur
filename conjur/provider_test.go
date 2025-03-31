package conjur

import (
	"testing"

	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// Mocking the Client
type MockClient struct {
	mock.Mock
}

func TestProvider(t *testing.T) {
	// Initialize the provider
	provider := Provider()

	// Validate provider configuration schema
	assert.NotNil(t, provider)
	assert.Contains(t, provider.DataSourcesMap, "conjur_secret")
	assert.Equal(t, len(provider.Schema), 6)

	// Test each schema key in the provider
	assert.Contains(t, provider.Schema, "appliance_url")
	assert.Contains(t, provider.Schema, "account")
	assert.Contains(t, provider.Schema, "login")
	assert.Contains(t, provider.Schema, "api_key")
	assert.Contains(t, provider.Schema, "ssl_cert")
	assert.Contains(t, provider.Schema, "ssl_cert_path")
}

func TestProviderConfig(t *testing.T) {
	data := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{
		"appliance_url": "https://conjur.example.com",
		"account":       "test_account",
		"login":         "test_login",
		"api_key":       "test_api_key",
		//"ssl_cert":      "test_ssl_cert",
		//"ssl_cert_path": "test_ssl_cert_path",
	})
	client, err := providerConfig(data)

	assert.NoError(t, err)
	assert.NotNil(t, client)
}

func TestHashFunction(t *testing.T) {
	input := "super_secret_value"
	expectedHash := "6ed76097ae92bf11e76dc16ad7149080460e01596735c950dea8f13515993ea8"
	result := hash(input)

	assert.Equal(t, expectedHash, result)
}

const testAccDataSourceConjurCustomAttributeConfigName = "data/vault/ADO_Secret/ado_secret_apikey/address"
const testAccDataSourceConjurCustomAttributeConfigValue = "10.0.1.56"

func TestAccConjurSecret(t *testing.T) {
	resourceName := "data.conjur_secret.secretValue"
	//expectedSecret := "secretValue"

	resource.Test(t, resource.TestCase{
		Providers: map[string]*schema.Provider{
			"conjur": Provider(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccConjurSecretConfig(),
				Check: resource.ComposeTestCheckFunc(
					// Check if the secret exists
					testAccCheckConjurSecretExists(resourceName),
					//resource.TestCheckResourceAttr(resourceName, "value", expectedSecret),
					resource.TestCheckResourceAttr(resourceName, "value", testAccDataSourceConjurCustomAttributeConfigValue),
				),
			},
		},
	})
}

func testAccConjurSecretConfig() string {
	return fmt.Sprintf(`
		variable "address" {
			default = "%s"
		}

		data "conjur_secret" "secretValue" {
			name = "${var.address}"
		}
		`,
		testAccDataSourceConjurCustomAttributeConfigName,
	)
}

func testAccCheckConjurSecretExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		// Ensure that the resource has an ID set
		if rs.Primary.ID == "" {
			return fmt.Errorf("resource has no ID set")
		}

		// Ensure that the value is set correctly in the state
		secretValue := rs.Primary.Attributes["value"]
		if secretValue == "" {
			return fmt.Errorf("secret value is empty")
		}

		return nil
	}
}
