package provider

import (
	"context"
	"testing"

	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
)

// TestEphemeralSecretsResource_Open_NilClient verifies that when the provider is not configured
// (nil client) Open emits the "Provider client not configured" warning, does not error, and does
// not populate the result - it returns before any BatchRetrieveSecrets call.
func TestEphemeralSecretsResource_Open_NilClient(t *testing.T) {
	e := &EphemeralSecretsResource{}

	testSchema := getEphemeralSecretsResourceTestSchema()
	req := ephemeral.OpenRequest{
		Config: tfsdk.Config{
			Raw:    secretsBatchConfigValue([]string{"data/a"}, types.BoolNull()),
			Schema: testSchema,
		},
	}
	resp := &ephemeral.OpenResponse{
		Result: tfsdk.EphemeralResultData{
			Raw:    tftypes.NewValue(tftypes.Object{}, nil),
			Schema: testSchema,
		},
	}

	e.Open(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError(), "expected no error diagnostics, got: %v", resp.Diagnostics.Errors())
	assertWarningContains(t, resp.Diagnostics, "Provider client not configured")
	assert.True(t, resp.Result.Raw.IsNull(), "expected result to not be populated")
}

// TestEphemeralSecretsResource_NamesValidators exercises the validators declared on the ephemeral
// resource's "names" attribute. These run at the framework validation layer before Open, so we
// pull them off the real schema and invoke them directly to stay in sync with the schema.
func TestEphemeralSecretsResource_NamesValidators(t *testing.T) {
	runNamesListValidators(t, getEphemeralSecretsResourceTestSchema().Attributes["names"].(schema.ListAttribute).Validators)
}

func TestEphemeralSecretsResource_Open(t *testing.T) {
	// The data source Read and the ephemeral Open share batchRetrieveSecretsToMap, so the
	// same table exercises both entry points; here we assert Open writes to resp.Result.
	for _, tt := range batchSecretsReadTestCases() {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			e := &EphemeralSecretsResource{client: mockV2}

			testSchema := getEphemeralSecretsResourceTestSchema()
			req := ephemeral.OpenRequest{
				Config: tfsdk.Config{
					Raw:    secretsBatchConfigValue(tt.names, tt.failOnError),
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
			e.Open(ctx, req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectedError, tt.errorContains)
			if tt.expectedWarning != "" {
				assertWarningContains(t, resp.Diagnostics, tt.expectedWarning)
			}
			if !tt.expectedError {
				var result secretsModel
				resp.Result.Get(ctx, &result)
				gotValues := map[string]string{}
				result.Values.ElementsAs(ctx, &gotValues, false)
				assert.Equal(t, tt.expectedValues, gotValues)
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func getEphemeralSecretsResourceTestSchema() schema.Schema {
	e := &EphemeralSecretsResource{}
	var schemaResp ephemeral.SchemaResponse
	e.Schema(context.Background(), ephemeral.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
