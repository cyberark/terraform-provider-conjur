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

func TestPermissionResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurPermissionResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful permission creation",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("developers"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/test"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("db-password"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/test"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
					types.StringValue("execute"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "permit") && contains(content, "developers") && contains(content, "db-password")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during creation",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("users"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/test"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("secret"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/test"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, mock.Anything, mock.Anything).Return(
					nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to load Permission policy",
		},
		{
			name: "permission with multiple privileges",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("admins"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/production"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("api-key"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/production"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
					types.StringValue("update"),
					types.StringValue("execute"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/production", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "permit") && contains(content, "admins")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "permission for host role",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("server-01"),
					Kind:   types.StringValue("host"),
					Branch: types.StringValue("data/servers"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("db-creds"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/secrets"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, mock.Anything, mock.Anything).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurPermissionResource{
				client: mockV2,
			}

			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPermissionTestSchema(),
				},
			}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPermissionTestSchema(),
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

func TestPermissionResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurPermissionResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
		expectedPrivs []string
	}{
		{
			name: "permission exists with read privilege",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("developers"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/test"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("db-password"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/test"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CheckPermissionForRole", "variable:data/test/db-password", "group:data/test/developers", "read").Return(true, nil)
				mockV2.On("CheckPermissionForRole", "variable:data/test/db-password", "group:data/test/developers", "update").Return(false, nil)
				mockV2.On("CheckPermissionForRole", "variable:data/test/db-password", "group:data/test/developers", "execute").Return(false, nil)
				mockV2.On("CheckPermissionForRole", "variable:data/test/db-password", "group:data/test/developers", "create").Return(false, nil)
			},
			expectedError: false,
			expectedPrivs: []string{"read"},
		},
		{
			name: "permission exists with multiple privileges",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("admins"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/prod"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("api-key"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/prod"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
					types.StringValue("update"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CheckPermissionForRole", "variable:data/prod/api-key", "group:data/prod/admins", "read").Return(true, nil)
				mockV2.On("CheckPermissionForRole", "variable:data/prod/api-key", "group:data/prod/admins", "update").Return(true, nil)
				mockV2.On("CheckPermissionForRole", "variable:data/prod/api-key", "group:data/prod/admins", "execute").Return(false, nil)
				mockV2.On("CheckPermissionForRole", "variable:data/prod/api-key", "group:data/prod/admins", "create").Return(false, nil)
			},
			expectedError: false,
			expectedPrivs: []string{"read", "update"},
		},
		{
			name: "API error checking permissions",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("users"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/test"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("secret"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/test"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CheckPermissionForRole", "variable:data/test/secret", "group:data/test/users", "read").Return(false, fmt.Errorf("connection error"))
			},
			expectedError: true,
			errorContains: "Unable to check permission via API",
		},
		{
			name: "no privileges exist",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("guests"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/test"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("restricted"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/test"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CheckPermissionForRole", "variable:data/test/restricted", "group:data/test/guests", "read").Return(false, nil)
				mockV2.On("CheckPermissionForRole", "variable:data/test/restricted", "group:data/test/guests", "update").Return(false, nil)
				mockV2.On("CheckPermissionForRole", "variable:data/test/restricted", "group:data/test/guests", "execute").Return(false, nil)
				mockV2.On("CheckPermissionForRole", "variable:data/test/restricted", "group:data/test/guests", "create").Return(false, nil)
			},
			expectedError: false,
			expectedPrivs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurPermissionResource{
				client: mockV2,
			}

			req := resource.ReadRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPermissionTestSchema(),
				},
			}
			resp := &resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPermissionTestSchema(),
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
				var result ConjurPermissionResourceModel
				resp.State.Get(ctx, &result)

				assert.Equal(t, len(tt.expectedPrivs), len(result.Privileges.Elements()))
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func TestPermissionResource_Update(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurPermissionResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful permission update",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("developers"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/test"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("db-password"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/test"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
					types.StringValue("update"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "permit") && contains(content, "developers")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during update",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("users"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/test"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("secret"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/test"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("execute"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, mock.Anything, mock.Anything).Return(
					nil, fmt.Errorf("unauthorized"))
			},
			expectedError: true,
			errorContains: "Unable to load Permission policy",
		},
		{
			name: "update to add more privileges",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("admins"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/prod"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("api-key"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/prod"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
					types.StringValue("update"),
					types.StringValue("execute"),
					types.StringValue("create"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/prod", mock.Anything).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurPermissionResource{
				client: mockV2,
			}

			req := resource.UpdateRequest{
				Plan: tfsdk.Plan{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPermissionTestSchema(),
				},
			}
			resp := &resource.UpdateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPermissionTestSchema(),
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

func TestPermissionResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurPermissionResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful permission deletion",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("developers"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/test"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("db-password"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/test"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "deny") && contains(content, "developers")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during deletion",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("users"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/test"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("secret"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/test"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, mock.Anything, mock.Anything).Return(
					nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to load Permission policy",
		},
		{
			name: "delete permission with multiple privileges",
			data: ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue("admins"),
					Kind:   types.StringValue("group"),
					Branch: types.StringValue("data/production"),
				},
				Resource: ResourceModel{
					Name:   types.StringValue("api-key"),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue("data/production"),
				},
				Privileges: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("read"),
					types.StringValue("update"),
					types.StringValue("execute"),
				}),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/production", mock.Anything).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurPermissionResource{
				client: mockV2,
			}

			req := resource.DeleteRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPermissionTestSchema(),
				},
			}
			resp := &resource.DeleteResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPermissionTestSchema(),
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

func getPermissionTestSchema() schema.Schema {
	r := &ConjurPermissionResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
