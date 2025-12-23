package provider

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestEmphemeralSecretDataSourceSchema(t *testing.T) {
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

func TestAPIEphemeralSecretDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerApiConfig + testRetrieveEphemeralSecret(),
				// Verify the ephemeral resource can be created successfully
				// Value validation is covered by unit and E2E tests
			},
		},
	})
}

func testRetrieveEphemeralSecret() string {
	return fmt.Sprintf(`
	ephemeral "conjur_secret" "test" {
		name = %[1]q
    }
	`, os.Getenv("TF_CONJUR_SECRET_VARIABLE"))
}

func TestEphemeralSecretResource_Open(t *testing.T) {
	tests := []struct {
		name          string
		config        EphemeralSecretResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
		expectedValue string
	}{
		{
			name: "successful secret retrieval",
			config: EphemeralSecretResourceModel{
				Name:    types.StringValue("db/password"),
				Version: types.Int64Null(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "db/password").Return([]byte("supersecret123"), nil)
			},
			expectedError: false,
			expectedValue: "supersecret123",
		},
		{
			name: "API error retrieving secret",
			config: EphemeralSecretResourceModel{
				Name:    types.StringValue("nonexistent/secret"),
				Version: types.Int64Null(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "nonexistent/secret").Return(nil, fmt.Errorf("404 Not Found"))
			},
			expectedError: true,
			errorContains: "Failed to retrieve secret",
		},
		{
			name: "permission denied error",
			config: EphemeralSecretResourceModel{
				Name:    types.StringValue("restricted/secret"),
				Version: types.Int64Null(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "restricted/secret").Return(nil, fmt.Errorf("401 Unauthorized"))
			},
			expectedError: true,
			errorContains: "Failed to retrieve secret",
		},
		{
			name: "secret with nested path",
			config: EphemeralSecretResourceModel{
				Name:    types.StringValue("prod/databases/mysql/password"),
				Version: types.Int64Null(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "prod/databases/mysql/password").Return([]byte("mysql_pass_789"), nil)
			},
			expectedError: false,
			expectedValue: "mysql_pass_789",
		},
		{
			name: "empty secret value",
			config: EphemeralSecretResourceModel{
				Name:    types.StringValue("empty/secret"),
				Version: types.Int64Null(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "empty/secret").Return([]byte(""), nil)
			},
			expectedError: false,
			expectedValue: "",
		},
		{
			name: "secret with version specified",
			config: EphemeralSecretResourceModel{
				Name:    types.StringValue("versioned/secret"),
				Version: types.Int64Value(2),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecretWithVersion", "versioned/secret", 2).Return([]byte("version2value"), nil)
			},
			expectedError: false,
			expectedValue: "version2value",
		},
		{
			name: "secret with special characters",
			config: EphemeralSecretResourceModel{
				Name:    types.StringValue("app/secret-key"),
				Version: types.Int64Null(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "app/secret-key").Return([]byte("key!@#$%^&*()"), nil)
			},
			expectedError: false,
			expectedValue: "key!@#$%^&*()",
		},
		{
			name: "secret with JSON value",
			config: EphemeralSecretResourceModel{
				Name:    types.StringValue("config/json"),
				Version: types.Int64Null(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "config/json").Return([]byte(`{"key":"value","nested":{"prop":"data"}}`), nil)
			},
			expectedError: false,
			expectedValue: `{"key":"value","nested":{"prop":"data"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &EphemeralSecretResource{
				client: mockV2,
			}

			testSchema := getEphemeralSecretResourceTestSchema()

			// Build config value with all schema attributes (name, version, value)
			// Value is computed so it will be null in the config
			configVal := tftypes.NewValue(
				tftypes.Object{
					AttributeTypes: map[string]tftypes.Type{
						"name":    tftypes.String,
						"version": tftypes.Number,
						"value":   tftypes.String,
					},
				},
				map[string]tftypes.Value{
					"name":    tftypes.NewValue(tftypes.String, tt.config.Name.ValueString()),
					"version": getVersionValue(tt.config.Version),
					"value":   tftypes.NewValue(tftypes.String, nil), // Computed, so null in config
				},
			)

			req := ephemeral.OpenRequest{
				Config: tfsdk.Config{
					Raw:    configVal,
					Schema: testSchema,
				},
			}
			resp := &ephemeral.OpenResponse{
				Result: tfsdk.EphemeralResultData{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: testSchema,
				},
			}

			ctx := context.Background()

			r.Open(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if strings.Contains(diag.Summary(), tt.errorContains) || strings.Contains(diag.Detail(), tt.errorContains) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error to contain: %s", tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
				var result EphemeralSecretResourceModel
				resp.Result.Get(ctx, &result)
				assert.Equal(t, tt.config.Name.ValueString(), result.Name.ValueString())
				if tt.config.Version.IsNull() {
					assert.True(t, result.Version.IsNull())
				} else {
					assert.Equal(t, tt.config.Version.ValueInt64(), result.Version.ValueInt64())
				}
				assert.Equal(t, tt.expectedValue, result.Value.ValueString())
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func getVersionValue(version types.Int64) tftypes.Value {
	if version.IsNull() {
		return tftypes.NewValue(tftypes.Number, nil)
	}
	return tftypes.NewValue(tftypes.Number, version.ValueInt64())
}

func getEphemeralSecretResourceTestSchema() schema.Schema {
	r := &EphemeralSecretResource{}
	var schemaResp ephemeral.SchemaResponse
	r.Schema(context.Background(), ephemeral.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
