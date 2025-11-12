package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMembershipResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          membershipResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
		expectedID    string
	}{
		{
			name: "successful creation",
			data: membershipResourceModel{
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/bob"),
			},
			setupMock: func(mockClientV2 *mocks.MockClientV2) {
				expectedMember := &conjurapi.GroupMember{
					ID:   "data/test/bob",
					Kind: "user",
				}
				mockClientV2.On("AddGroupMember", mock.Anything, mock.Anything).
					Return(expectedMember, nil)
			},
			expectedError: false,
			expectedID:    "data/test/test-users:user:data/test/bob",
		},
		{
			name: "invalid member kind",
			data: membershipResourceModel{
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("invalid"),
				MemberID:   types.StringValue("data/test/bob"),
			},
			setupMock:     func(mockClientV2 *mocks.MockClientV2) {},
			expectedError: true,
			errorContains: "Invalid member_kind",
		},
		{
			name: "api error on add",
			data: membershipResourceModel{
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/bob"),
			},
			setupMock: func(mockClientV2 *mocks.MockClientV2) {
				mockClientV2.On("AddGroupMember", "data/test/test-users", mock.Anything).
					Return(nil, fmt.Errorf("API error"))
			},
			expectedError: true,
			errorContains: "Failed to add group member",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClientV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockClientV2)

			r := &conjurMembershipResource{
				client: mockClientV2,
			}

			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getMembershipTestSchema(),
				},
			}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getMembershipTestSchema(),
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
				var result membershipResourceModel
				resp.State.Get(ctx, &result)
				assert.Equal(t, tt.expectedID, result.ID.ValueString())
			}
		})
	}
}

func TestMembershipResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          membershipResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		shouldRemove  bool
	}{
		{
			name: "membership exists",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-users:user:data/test/bob"),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/bob"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				config := conjurapi.Config{
					Account: "conjur",
				}
				mockClient.On("GetConfig").Return(config)
				mockClient.On("RoleMemberships", "conjur:user:data/test/bob").Return(
					[]map[string]interface{}{
						{"roleid": "conjur:group:data/test/test-users"},
						{"roleid": "conjur:group:data/test/other-group"},
					},
					nil,
				)
			},
			expectedError: false,
			shouldRemove:  false,
		},
		{
			name: "membership exists with 'role' field",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-users:user:data/test/alice"),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/alice"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				config := conjurapi.Config{
					Account: "conjur",
				}
				mockClient.On("GetConfig").Return(config)
				mockClient.On("RoleMemberships", "conjur:user:data/test/alice").Return(
					[]map[string]interface{}{
						{"role": "conjur:group:data/test/test-users"},
					},
					nil,
				)
			},
			expectedError: false,
			shouldRemove:  false,
		},
		{
			name: "membership exists with 'id' field",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-users:host:data/test/server1"),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("host"),
				MemberID:   types.StringValue("data/test/server1"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				config := conjurapi.Config{
					Account: "conjur",
				}
				mockClient.On("GetConfig").Return(config)
				mockClient.On("RoleMemberships", "conjur:host:data/test/server1").Return(
					[]map[string]interface{}{
						{"id": "conjur:group:data/test/test-users"},
					},
					nil,
				)
			},
			expectedError: false,
			shouldRemove:  false,
		},
		{
			name: "membership not found - removes from state",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-users:user:data/test/charlie"),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/charlie"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				config := conjurapi.Config{
					Account: "conjur",
				}
				mockClient.On("GetConfig").Return(config)
				mockClient.On("RoleMemberships", "conjur:user:data/test/charlie").Return(
					[]map[string]interface{}{
						{"roleid": "conjur:group:data/test/other-group"},
					},
					nil,
				)
			},
			expectedError: false,
			shouldRemove:  true,
		},
		{
			name: "API error - removes from state",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-users:user:data/test/dave"),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/dave"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				config := conjurapi.Config{
					Account: "conjur",
				}
				mockClient.On("GetConfig").Return(config)
				mockClient.On("RoleMemberships", "conjur:user:data/test/dave").Return(
					nil,
					fmt.Errorf("API connection error"),
				)
			},
			expectedError: false,
			shouldRemove:  true,
		},
		{
			name: "invalid member kind",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-users:invalid:data/test/eve"),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("invalid"),
				MemberID:   types.StringValue("data/test/eve"),
			},
			setupMock:     func(mockClient *mocks.MockClientV2) {},
			expectedError: true,
			shouldRemove:  false,
		},
		{
			name: "empty ID gets populated",
			data: membershipResourceModel{
				ID:         types.StringValue(""),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/frank"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				config := conjurapi.Config{
					Account: "conjur",
				}
				mockClient.On("GetConfig").Return(config)
				mockClient.On("RoleMemberships", "conjur:user:data/test/frank").Return(
					[]map[string]interface{}{
						{"roleid": "conjur:group:data/test/test-users"},
					},
					nil,
				)
			},
			expectedError: false,
			shouldRemove:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mocks.NewMockClientV2(t)
			tt.setupMock(mockClient)

			r := &conjurMembershipResource{
				client: mockClient,
			}

			req := resource.ReadRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getMembershipTestSchema(),
				},
			}
			resp := &resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getMembershipTestSchema(),
				},
			}

			ctx := context.Background()
			req.State.Set(ctx, &tt.data)

			r.Read(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
			} else {
				assert.False(t, resp.Diagnostics.HasError())

				if tt.shouldRemove {
					// State should be removed
					var result membershipResourceModel
					diag := resp.State.Get(ctx, &result)
					assert.True(t, diag.HasError() || result.ID.IsNull())
				} else {
					// State should still exist
					var result membershipResourceModel
					resp.State.Get(ctx, &result)
					assert.False(t, result.ID.IsNull())
					assert.NotEmpty(t, result.ID.ValueString())
				}
			}
			mockClient.AssertExpectations(t)
		})
	}
}

func TestMembershipResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          membershipResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful deletion",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-users:user:data/test/bob"),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/bob"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				expectedMember := conjurapi.GroupMember{
					ID:   "data/test/bob",
					Kind: "user",
				}
				mockClient.On("RemoveGroupMember", "data/test/test-users", expectedMember).
					Return([]byte{}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful deletion with host member",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-hosts:host:data/test/server1"),
				GroupID:    types.StringValue("data/test/test-hosts"),
				MemberKind: types.StringValue("host"),
				MemberID:   types.StringValue("data/test/server1"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				expectedMember := conjurapi.GroupMember{
					ID:   "data/test/server1",
					Kind: "host",
				}
				mockClient.On("RemoveGroupMember", "data/test/test-hosts", expectedMember).
					Return([]byte{}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful deletion with group member",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/parent-group:group:data/test/child-group"),
				GroupID:    types.StringValue("data/test/parent-group"),
				MemberKind: types.StringValue("group"),
				MemberID:   types.StringValue("data/test/child-group"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				expectedMember := conjurapi.GroupMember{
					ID:   "data/test/child-group",
					Kind: "group",
				}
				mockClient.On("RemoveGroupMember", "data/test/parent-group", expectedMember).
					Return([]byte{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error on delete",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-users:user:data/test/alice"),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/alice"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				mockClient.On("RemoveGroupMember", "data/test/test-users", mock.MatchedBy(func(m conjurapi.GroupMember) bool {
					return m.ID == "data/test/alice" && m.Kind == "user"
				})).Return(nil, fmt.Errorf("API connection error"))
			},
			expectedError: true,
			errorContains: "Unable to remove group member",
		},
		{
			name: "member not found error",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-users:user:data/test/charlie"),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/charlie"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				mockClient.On("RemoveGroupMember", "data/test/test-users", mock.MatchedBy(func(m conjurapi.GroupMember) bool {
					return m.ID == "data/test/charlie" && m.Kind == "user"
				})).Return(nil, fmt.Errorf("404 Not Found"))
			},
			expectedError: true,
			errorContains: "Unable to remove group member",
		},
		{
			name: "unauthorized error",
			data: membershipResourceModel{
				ID:         types.StringValue("data/test/test-users:user:data/test/dave"),
				GroupID:    types.StringValue("data/test/test-users"),
				MemberKind: types.StringValue("user"),
				MemberID:   types.StringValue("data/test/dave"),
			},
			setupMock: func(mockClient *mocks.MockClientV2) {
				mockClient.On("RemoveGroupMember", "data/test/test-users", mock.MatchedBy(func(m conjurapi.GroupMember) bool {
					return m.ID == "data/test/dave" && m.Kind == "user"
				})).Return(nil, fmt.Errorf("401 Unauthorized"))
			},
			expectedError: true,
			errorContains: "Unable to remove group member",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mocks.NewMockClientV2(t)
			tt.setupMock(mockClient)

			r := &conjurMembershipResource{
				client: mockClient,
			}

			req := resource.DeleteRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getMembershipTestSchema(),
				},
			}
			resp := &resource.DeleteResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getMembershipTestSchema(),
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
			mockClient.AssertExpectations(t)
		})
	}
}

func getMembershipTestSchema() schema.Schema {
	r := &conjurMembershipResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}

func contains(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || len(substr) == 0 ||
		(len(str) > 0 && len(substr) > 0 && hasSubstring(str, substr)))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
