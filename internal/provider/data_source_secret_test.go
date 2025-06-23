package provider

import (
	"context"
	"os"
	"fmt"
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
				Config: providerApiConfig + testRetrievSecret(),
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
				Config: providerIAMConfig + testRetrievSecret(),
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
				Config: providerAzureConfig + testRetrievSecret(),
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
				Config: providerGCPConfig + testRetrievSecret(),
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
				Config: providerJWTConfig + testJwtRetrievSecret(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.conjur_secret.test", "value", os.Getenv("TF_JWT_SECRET_VALUE")),
				),
			},
		},
	})
}

func testRetrievSecret() string {
	return fmt.Sprintf(`
	data "conjur_secret" "test" {
		name               = %[1]q
    }
	`, os.Getenv("TF_CONJUR_SECRET_VARIABLE"))
}

func testJwtRetrievSecret() string {
	return fmt.Sprintf(`
	data "conjur_secret" "test" {
		name               = %[1]q
    }
	`, os.Getenv("TF_JWT_CONJUR_SECRET_VARIABLE"))
}