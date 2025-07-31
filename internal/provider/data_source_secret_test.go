package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestSecretDataSourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaRequest := fwdatasource.SchemaRequest{}
	schemaResponse := &fwdatasource.SchemaResponse{}

	// Instantiate the datasource.DataSource and call its Schema method
	NewSecretDataSource().Schema(ctx, schemaRequest, schemaResponse)

	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema method diagnostics: %+v", schemaResponse.Diagnostics)
	}

	// Validate the schema
	diagnostics := schemaResponse.Schema.ValidateImplementation(ctx)

	if diagnostics.HasError() {
		t.Fatalf("Schema validation diagnostics: %+v", diagnostics)
	}
}

func TestAPISecretDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerApiConfig + testRetrieveSecret(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.conjur_secret.test", "value", os.Getenv("TF_SECRET_VALUE")),
				),
			},
		},
	})
}

func TestIAMSecretDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerIAMConfig + testRetrieveSecret(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.conjur_secret.test", "value", os.Getenv("TF_SECRET_VALUE")),
				),
			},
		},
	})
}

func TestAzureSecretDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerAzureConfig + testRetrieveSecret(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.conjur_secret.test", "value", os.Getenv("TF_SECRET_VALUE")),
				),
			},
		},
	})
}

func TestGCPSecretDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerGCPConfig + testRetrieveSecret(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.conjur_secret.test", "value", os.Getenv("TF_SECRET_VALUE")),
				),
			},
		},
	})
}

func TestJWTSecretDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerJWTConfig + testJwtRetrieveSecret(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.conjur_secret.test", "value", os.Getenv("TF_JWT_SECRET_VALUE")),
				),
			},
		},
	})
}

func TestConfigFromEnvVars(t *testing.T) {
    resource.Test(t, resource.TestCase{
        ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
        Steps: []resource.TestStep{
            {
                Config: `provider "conjur" {}` + testRetrieveSecret(),
                Check: resource.ComposeTestCheckFunc(
                    resource.TestCheckResourceAttr("data.conjur_secret.test", "value", os.Getenv("TF_SECRET_VALUE")),
                ),
            },
        },
    })
}

func testRetrieveSecret() string {
	return fmt.Sprintf(`
	data "conjur_secret" "test" {
		name               = %[1]q
    }
	`, os.Getenv("TF_CONJUR_SECRET_VARIABLE"))
}

func testJwtRetrieveSecret() string {
	return fmt.Sprintf(`
	data "conjur_secret" "test" {
		name               = %[1]q
    }
	`, os.Getenv("TF_JWT_CONJUR_SECRET_VARIABLE"))
}