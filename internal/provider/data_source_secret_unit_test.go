package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
)

func TestSecretDataSource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          SecretDataSourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
		expectedValue string
	}{
		{
			name: "successful secret retrieval",
			data: SecretDataSourceModel{
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
			data: SecretDataSourceModel{
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
			data: SecretDataSourceModel{
				Name:    types.StringValue("restricted/secret"),
				Version: types.Int64Null(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "restricted/secret").Return(nil, fmt.Errorf("403 Forbidden"))
			},
			expectedError: true,
			errorContains: "Failed to retrieve secret",
		},
		{
			name: "secret with nested path",
			data: SecretDataSourceModel{
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
			data: SecretDataSourceModel{
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
			data: SecretDataSourceModel{
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
			data: SecretDataSourceModel{
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
			data: SecretDataSourceModel{
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

			d := &SecretDataSource{
				client: mockV2,
			}

			testSchema := getSecretDataSourceTestSchema()

			var versionVal tftypes.Value
			if tt.data.Version.IsNull() {
				versionVal = tftypes.NewValue(tftypes.Number, nil)
			} else {
				versionVal = tftypes.NewValue(tftypes.Number, tt.data.Version.ValueInt64())
			}

			configVal := tftypes.NewValue(
				tftypes.Object{
					AttributeTypes: map[string]tftypes.Type{
						"name":    tftypes.String,
						"version": tftypes.Number,
						"value":   tftypes.String,
					},
				},
				map[string]tftypes.Value{
					"name":    tftypes.NewValue(tftypes.String, tt.data.Name.ValueString()),
					"version": versionVal,
					"value":   tftypes.NewValue(tftypes.String, nil),
				},
			)

			req := datasource.ReadRequest{
				Config: tfsdk.Config{
					Raw:    configVal,
					Schema: testSchema,
				},
			}
			resp := &datasource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: testSchema,
				},
			}

			ctx := context.Background()

			d.Read(ctx, req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectedError, tt.errorContains)
			if !tt.expectedError {
				var result SecretDataSourceModel
				resp.State.Get(ctx, &result)
				assert.Equal(t, tt.data.Name.ValueString(), result.Name.ValueString())
				assert.Equal(t, tt.expectedValue, result.Value.ValueString())
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func getSecretDataSourceTestSchema() schema.Schema {
	d := &SecretDataSource{}
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
