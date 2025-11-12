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
		data          secretDataSourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
		expectedValue string
	}{
		{
			name: "successful secret retrieval",
			data: secretDataSourceModel{
				Name:    types.StringValue("db/password"),
				Version: types.StringNull(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "db/password").Return([]byte("supersecret123"), nil)
			},
			expectedError: false,
			expectedValue: "supersecret123",
		},
		{
			name: "API error retrieving secret",
			data: secretDataSourceModel{
				Name:    types.StringValue("nonexistent/secret"),
				Version: types.StringNull(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "nonexistent/secret").Return(nil, fmt.Errorf("404 Not Found"))
			},
			expectedError: true,
			errorContains: "Failed to retrieve secret",
		},
		{
			name: "permission denied error",
			data: secretDataSourceModel{
				Name:    types.StringValue("restricted/secret"),
				Version: types.StringNull(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "restricted/secret").Return(nil, fmt.Errorf("403 Forbidden"))
			},
			expectedError: true,
			errorContains: "Failed to retrieve secret",
		},
		{
			name: "secret with nested path",
			data: secretDataSourceModel{
				Name:    types.StringValue("prod/databases/mysql/password"),
				Version: types.StringNull(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "prod/databases/mysql/password").Return([]byte("mysql_pass_789"), nil)
			},
			expectedError: false,
			expectedValue: "mysql_pass_789",
		},
		{
			name: "empty secret value",
			data: secretDataSourceModel{
				Name:    types.StringValue("empty/secret"),
				Version: types.StringNull(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "empty/secret").Return([]byte(""), nil)
			},
			expectedError: false,
			expectedValue: "",
		},
		{
			name: "secret with version specified",
			data: secretDataSourceModel{
				Name:    types.StringValue("versioned/secret"),
				Version: types.StringValue("2"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "versioned/secret").Return([]byte("version2value"), nil)
			},
			expectedError: false,
			expectedValue: "version2value",
		},
		{
			name: "secret with special characters",
			data: secretDataSourceModel{
				Name:    types.StringValue("app/secret-key"),
				Version: types.StringNull(),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RetrieveSecret", "app/secret-key").Return([]byte("key!@#$%^&*()"), nil)
			},
			expectedError: false,
			expectedValue: "key!@#$%^&*()",
		},
		{
			name: "secret with JSON value",
			data: secretDataSourceModel{
				Name:    types.StringValue("config/json"),
				Version: types.StringNull(),
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

			d := &secretDataSource{
				client: mockV2,
			}

			testSchema := getSecretDataSourceTestSchema()

			configVal := tftypes.NewValue(
				tftypes.Object{
					AttributeTypes: map[string]tftypes.Type{
						"name":    tftypes.String,
						"version": tftypes.String,
						"value":   tftypes.String,
					},
				},
				map[string]tftypes.Value{
					"name":    tftypes.NewValue(tftypes.String, tt.data.Name.ValueString()),
					"version": tftypes.NewValue(tftypes.String, nil),
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

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if contains(diag.Summary(), tt.errorContains) || contains(diag.Detail(), tt.errorContains) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error to contain: %s", tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
				var result secretDataSourceModel
				resp.State.Get(ctx, &result)
				assert.Equal(t, tt.data.Name.ValueString(), result.Name.ValueString())
				assert.Equal(t, tt.expectedValue, result.Value.ValueString())
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func getSecretDataSourceTestSchema() schema.Schema {
	d := &secretDataSource{}
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
