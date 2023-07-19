package conjur

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testAccProviders map[string]*schema.Provider
var testAccProvider *schema.Provider

func init() {
	testAccProvider = Provider()
	testAccProviders = map[string]*schema.Provider{
		"conjur": testAccProvider,
	}
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func setEnv() {
	os.Setenv("CONJUR_APPLIANCE_URL", "https://conjurcloudint.secretsmgr.company.cloud/api")
	os.Setenv("CONJUR_ACCOUNT", "conjur")
	os.Setenv("CONJUR_AUTHN_LOGIN", "hostname")
	os.Setenv("CONJUR_AUTHN_API_KEY", "2cv7g......")
}

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("CONJUR_APPLIANCE_URL"); v == "" {
		t.Fatal("CONJUR_APPLIANCE_URL must be set for acceptance tests")
	}

	if v := os.Getenv("CONJUR_ACCOUNT"); v == "" {
		t.Fatal("CONJUR_ACCOUNT must be set for acceptance tests")
	}

	if v := os.Getenv("CONJUR_AUTHN_LOGIN"); v == "" {
		t.Fatal("CONJUR_AUTHN_LOGIN must be set for acceptance tests")
	}

	if v := os.Getenv("CONJUR_AUTHN_API_KEY"); v == "" {
		t.Fatal("CONJUR_AUTHN_API_KEY must be set for acceptance tests")
	}
}

func testAccProviderMeta(t *testing.T) (interface{}, error) {
	t.Helper()
	d := schema.TestResourceDataRaw(t, testAccProvider.Schema, make(map[string]interface{}))
	return providerConfig(d)
}

func TestProvider_conjur_detail(t *testing.T) {
	setEnv()
	_, err := testAccProviderMeta(t)

	if err != nil {
		t.Fatalf("bad: %s", err)
	}
	assert.Equal(t, "2697cbd4172c14f36c2c51e160da27b7d5c9a6073bd1e3d1607340130c13d210", hash(testAccDataSourceConjurCustomAttributeConfigValue))
}

func TestAccDataSourceConjurCustomAttribute_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceConjurCustomAttributeConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						"data.conjur_secret.secretValue",
						"value",
						testAccDataSourceConjurCustomAttributeConfigValue,
					),
				),
			},
		},
	})
}

const testAccDataSourceConjurCustomAttributeConfigName = "data/vault/secret-safe/apikey/address"
const testAccDataSourceConjurCustomAttributeConfigValue = "10.0.1.56"

func testAccDataSourceConjurCustomAttributeConfig() string {
	return fmt.Sprintf(`
		variable "ipaddress" {
			default = "%s"
		}

		data "conjur_secret" "secretValue" {
			name = "${var.ipaddress}"
		}
		`,
		testAccDataSourceConjurCustomAttributeConfigName,
	)
}

func TestProvider_HasChildDataSources(t *testing.T) {
	expectedDataSources := []string{
		"conjur_secret",
	}

	dataSources := Provider().DataSourcesMap
	require.Equal(t, len(expectedDataSources), len(dataSources), "There are an unexpected number of registered data sources")

	for _, resource := range expectedDataSources {
		require.Contains(t, dataSources, resource, "An expected data source was not registered")
		require.NotNil(t, dataSources[resource], "A data source cannot have a nil schema")
	}
}

func TestProvider_SchemaIsValid(t *testing.T) {
	type testParams struct {
		name     string
		required bool
	}

	tests := []testParams{
		{"appliance_url", false},
		{"account", false},
		{"login", false},
		{"api_key", false},
		{"ssl_cert", false},
		{"ssl_cert_path", false},
	}

	schema := Provider().Schema
	require.Equal(t, len(tests), len(schema), "There are an unexpected number of properties in the schema")

	for _, test := range tests {
		require.Contains(t, schema, test.name, "An expected property was not found in the schema")
		require.NotNil(t, schema[test.name], "A property in the schema cannot have a nil value")
		require.Equal(t, test.required, schema[test.name].Required, "A property in the schema has an incorrect required value")
	}
}
