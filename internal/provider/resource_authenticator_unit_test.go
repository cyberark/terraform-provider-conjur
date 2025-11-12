package provider

import (
	"context"
	"fmt"
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

func TestAuthenticatorResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurAuthenticatorResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful JWT authenticator creation",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("test-jwt"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateAuthenticator", mock.MatchedBy(func(auth *conjurapi.AuthenticatorBase) bool {
					return auth.Type == "authn-jwt" && auth.Name == "test-jwt"
				})).Return(&conjurapi.AuthenticatorResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during creation",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("error-auth"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateAuthenticator", mock.Anything).Return(nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to create authenticator",
		},
		{
			name: "creation with data and annotations",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("prod-jwt"),
				Enabled: types.BoolValue(true),
				Data: &ConjurAuthenticatorDataModel{
					Audience: types.StringValue("https://example.com"),
					Issuer:   types.StringValue("https://issuer.com"),
				},
				Annotations: map[string]string{"env": "prod", "team": "platform"},
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateAuthenticator", mock.MatchedBy(func(auth *conjurapi.AuthenticatorBase) bool {
					return auth.Type == "authn-jwt" && auth.Name == "prod-jwt" && len(auth.Annotations) == 2
				})).Return(&conjurapi.AuthenticatorResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "creation with owner",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-oidc"),
				Name:    types.StringValue("oidc-auth"),
				Enabled: types.BoolValue(false),
				Owner: types.ObjectValueMust(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}, map[string]attr.Value{
					"kind": types.StringValue("group"),
					"id":   types.StringValue("admins"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateAuthenticator", mock.MatchedBy(func(auth *conjurapi.AuthenticatorBase) bool {
					return auth.Type == "authn-oidc" && auth.Owner != nil && auth.Owner.Kind == "group"
				})).Return(&conjurapi.AuthenticatorResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "creation with subtype",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("github-jwt"),
				Subtype: types.StringValue("github"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateAuthenticator", mock.MatchedBy(func(auth *conjurapi.AuthenticatorBase) bool {
					return auth.Type == "authn-jwt" && auth.Subtype != nil && *auth.Subtype == "github"
				})).Return(&conjurapi.AuthenticatorResponse{}, nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurAuthenticatorResource{
				client: mockV2,
			}

			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getAuthenticatorTestSchema(),
				},
			}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getAuthenticatorTestSchema(),
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

func TestAuthenticatorResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurAuthenticatorResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "authenticator exists",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("test-jwt"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetAuthenticator", "authn-jwt", "test-jwt").Return(&conjurapi.AuthenticatorResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error reading authenticator",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("error-auth"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetAuthenticator", "authn-jwt", "error-auth").Return(
					nil, fmt.Errorf("not found"))
			},
			expectedError: true,
			errorContains: "Unable to read authenticator",
		},
		{
			name: "authenticator with data exists",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-oidc"),
				Name:    types.StringValue("oidc-prod"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetAuthenticator", "authn-oidc", "oidc-prod").Return(&conjurapi.AuthenticatorResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "authenticator with owner exists",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("jwt-secure"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectValueMust(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}, map[string]attr.Value{
					"kind": types.StringValue("group"),
					"id":   types.StringValue("security"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("GetAuthenticator", "authn-jwt", "jwt-secure").Return(&conjurapi.AuthenticatorResponse{}, nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurAuthenticatorResource{
				client: mockV2,
			}

			req := resource.ReadRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getAuthenticatorTestSchema(),
				},
			}
			resp := &resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getAuthenticatorTestSchema(),
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

func TestAuthenticatorResource_Update(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurAuthenticatorResourceModel
		state         ConjurAuthenticatorResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "enable authenticator",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("test-jwt"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			state: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("test-jwt"),
				Enabled: types.BoolValue(false),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("EnableAuthenticator", "authn-jwt", "test-jwt", true).Return(nil)
			},
			expectedError: false,
		},
		{
			name: "disable authenticator",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-oidc"),
				Name:    types.StringValue("oidc-auth"),
				Enabled: types.BoolValue(false),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			state: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-oidc"),
				Name:    types.StringValue("oidc-auth"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("EnableAuthenticator", "authn-oidc", "oidc-auth", false).Return(nil)
			},
			expectedError: false,
		},
		{
			name: "API error during update",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("error-auth"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			state: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("error-auth"),
				Enabled: types.BoolValue(false),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("EnableAuthenticator", "authn-jwt", "error-auth", true).Return(
					fmt.Errorf("permission denied"))
			},
			expectedError: false,
		},
		{
			name: "update with owner preserved from state",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("jwt-prod"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			state: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("jwt-prod"),
				Enabled: types.BoolValue(false),
				Owner: types.ObjectValueMust(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}, map[string]attr.Value{
					"kind": types.StringValue("group"),
					"id":   types.StringValue("admins"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("EnableAuthenticator", "authn-jwt", "jwt-prod", true).Return(nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurAuthenticatorResource{
				client: mockV2,
			}

			req := resource.UpdateRequest{
				Plan: tfsdk.Plan{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getAuthenticatorTestSchema(),
				},
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getAuthenticatorTestSchema(),
				},
			}
			resp := &resource.UpdateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getAuthenticatorTestSchema(),
				},
			}

			ctx := context.Background()
			req.Plan.Set(ctx, &tt.data)
			req.State.Set(ctx, &tt.state)

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

func TestAuthenticatorResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurAuthenticatorResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful deletion",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("test-jwt"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("DeleteAuthenticator", "authn-jwt", "test-jwt").Return(nil)
			},
			expectedError: false,
		},
		{
			name: "API error during deletion",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-oidc"),
				Name:    types.StringValue("error-auth"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("DeleteAuthenticator", "authn-oidc", "error-auth").Return(
					fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to delete authenticator",
		},
		{
			name: "404 not found error",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-jwt"),
				Name:    types.StringValue("nonexistent-auth"),
				Enabled: types.BoolValue(true),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("DeleteAuthenticator", "authn-jwt", "nonexistent-auth").Return(
					fmt.Errorf("404 Not Found"))
			},
			expectedError: true,
			errorContains: "Unable to delete authenticator",
		},
		{
			name: "deletion of authenticator with annotations",
			data: ConjurAuthenticatorResourceModel{
				Type:        types.StringValue("authn-jwt"),
				Name:        types.StringValue("prod-jwt"),
				Enabled:     types.BoolValue(true),
				Annotations: map[string]string{"env": "prod"},
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("DeleteAuthenticator", "authn-jwt", "prod-jwt").Return(nil)
			},
			expectedError: false,
		},
		{
			name: "deletion of disabled authenticator",
			data: ConjurAuthenticatorResourceModel{
				Type:    types.StringValue("authn-ldap"),
				Name:    types.StringValue("ldap-auth"),
				Enabled: types.BoolValue(false),
				Owner: types.ObjectNull(map[string]attr.Type{
					"kind": types.StringType,
					"id":   types.StringType,
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("DeleteAuthenticator", "authn-ldap", "ldap-auth").Return(nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurAuthenticatorResource{
				client: mockV2,
			}

			req := resource.DeleteRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getAuthenticatorTestSchema(),
				},
			}
			resp := &resource.DeleteResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getAuthenticatorTestSchema(),
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

func getAuthenticatorTestSchema() schema.Schema {
	r := &ConjurAuthenticatorResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
