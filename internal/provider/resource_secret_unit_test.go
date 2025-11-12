package provider

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSecretResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurSecretResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful creation with minimal fields",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("db-password"),
				Branch: types.StringValue("/data/test"),
				Value:  types.StringValue("secret123"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateStaticSecret", mock.MatchedBy(func(s conjurapi.StaticSecret) bool {
					return s.Name == "db-password" && s.Branch == "/data/test" && s.Value == "secret123"
				})).Return(&conjurapi.StaticSecretResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during creation",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("error-secret"),
				Branch: types.StringValue("/data/test"),
				Value:  types.StringValue("secret123"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateStaticSecret", mock.Anything).Return(nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to create secret",
		},
		{
			name: "creation with all optional fields",
			data: ConjurSecretResourceModel{
				Name:     types.StringValue("api-key"),
				Branch:   types.StringValue("/data/production"),
				Value:    types.StringValue("supersecret"),
				MimeType: types.StringValue("application/json"),
				Owner: types.ObjectValueMust(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}, map[string]attr.Value{
					"kind": types.StringValue("group"),
					"id":   types.StringValue("admins"),
				}),
				Annotations: map[string]string{"env": "prod", "team": "platform"},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateStaticSecret", mock.MatchedBy(func(s conjurapi.StaticSecret) bool {
					return s.Name == "api-key" &&
						s.Branch == "/data/production" &&
						s.MimeType == "application/json" &&
						s.Owner != nil &&
						s.Owner.Kind == "group" &&
						len(s.Annotations) == 2
				})).Return(&conjurapi.StaticSecretResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "creation with permissions",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("shared-secret"),
				Branch: types.StringValue("/data/test"),
				Value:  types.StringValue("secret123"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
				Permissions: []ConjurSecretPermission{
					{
						Subject: ConjurSecretSubject{
							Id:   types.StringValue("user:bob"),
							Kind: types.StringValue("user"),
						},
						Privileges: types.ListValueMust(types.StringType, []attr.Value{
							types.StringValue("read"),
							types.StringValue("execute"),
						}),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateStaticSecret", mock.MatchedBy(func(s conjurapi.StaticSecret) bool {
					return s.Name == "shared-secret" && len(s.Permissions) == 1
				})).Return(&conjurapi.StaticSecretResponse{}, nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurSecretResource{
				client: mockV2,
			}

			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getSecretTestSchema(),
				},
			}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getSecretTestSchema(),
				},
			}

			ctx := context.Background()
			req.Plan.Set(ctx, &tt.data)

			r.Create(ctx, req, resp)

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
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func TestSecretResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurSecretResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "secret exists",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("test-secret"),
				Branch: types.StringValue("/data/test"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetStaticSecretDetails", "/data/test/test-secret").Return(&conjurapi.StaticSecretResponse{}, nil)
				mockV2.On("RetrieveSecret", "data/test/test-secret").Return([]byte("secret-value"), nil)
			},
			expectedError: false,
		},
		{
			name: "secret exists with owner and annotations",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("prod-secret"),
				Branch: types.StringValue("/data/production"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetStaticSecretDetails", "/data/production/prod-secret").Return(&conjurapi.StaticSecretResponse{}, nil)
				mockV2.On("RetrieveSecret", "data/production/prod-secret").Return([]byte("prod-value"), nil)
			},
			expectedError: false,
		},
		{
			name: "API error reading secret",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("error-secret"),
				Branch: types.StringValue("/data/test"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetStaticSecretDetails", "/data/test/error-secret").Return(
					nil, fmt.Errorf("connection error"))
			},
			expectedError: true,
			errorContains: "Unable to check if secret",
		},
		{
			name: "secret exists but value cannot be retrieved",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("restricted-secret"),
				Branch: types.StringValue("/data/test"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetStaticSecretDetails", "/data/test/restricted-secret").Return(&conjurapi.StaticSecretResponse{}, nil)
				mockV2.On("RetrieveSecret", "data/test/restricted-secret").Return(
					nil, fmt.Errorf("403 Forbidden"))
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurSecretResource{
				client: mockV2,
			}

			req := resource.ReadRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getSecretTestSchema(),
				},
			}
			resp := &resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getSecretTestSchema(),
				},
			}

			ctx := context.Background()
			req.State.Set(ctx, &tt.data)

			r.Read(ctx, req, resp)

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
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func TestSecretResource_Update(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurSecretResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful value update",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("test-secret"),
				Branch: types.StringValue("/data/test"),
				Value:  types.StringValue("new-secret-value"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("AddSecret", "data/test/test-secret", "new-secret-value").Return(nil)
			},
			expectedError: false,
		},
		{
			name: "API error during update",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("error-secret"),
				Branch: types.StringValue("/data/test"),
				Value:  types.StringValue("new-value"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("AddSecret", "data/test/error-secret", "new-value").Return(
					fmt.Errorf("permission denied"))
			},
			expectedError: false,
		},
		{
			name: "update secret in nested branch",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("api-key"),
				Branch: types.StringValue("/data/production/app"),
				Value:  types.StringValue("updated-key"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("AddSecret", "data/production/app/api-key", "updated-key").Return(nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurSecretResource{
				client: mockV2,
			}

			req := resource.UpdateRequest{
				Plan: tfsdk.Plan{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getSecretTestSchema(),
				},
			}
			resp := &resource.UpdateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getSecretTestSchema(),
				},
			}

			ctx := context.Background()
			req.Plan.Set(ctx, &tt.data)

			r.Update(ctx, req, resp)

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
			}
			mockV2.AssertExpectations(t)
		})
	}
}

func TestSecretResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurSecretResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful deletion",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("test-secret"),
				Branch: types.StringValue("/data/test"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.MatchedBy(func(policy io.Reader) bool {
					// Read policy content to verify
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "!delete") && contains(content, "test-secret")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during deletion",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("error-secret"),
				Branch: types.StringValue("/data/test"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.Anything).Return(
					nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to load Secret Delete policy",
		},
		{
			name: "deletion from nested branch",
			data: ConjurSecretResourceModel{
				Name:   types.StringValue("api-key"),
				Branch: types.StringValue("/data/production/app"),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/production/app", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "!delete") && contains(content, "api-key")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurSecretResource{
				client: mockV2,
			}

			req := resource.DeleteRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getSecretTestSchema(),
				},
			}
			resp := &resource.DeleteResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getSecretTestSchema(),
				},
			}

			ctx := context.Background()
			req.State.Set(ctx, &tt.data)

			r.Delete(ctx, req, resp)

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
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func getSecretTestSchema() schema.Schema {
	r := &ConjurSecretResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
