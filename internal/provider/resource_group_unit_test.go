package provider

import (
	"context"
	"fmt"
	"io"
	"strings"
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

func TestGroupResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurGroupResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful group creation with minimal fields",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("developers"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "group") && contains(content, "developers")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during creation",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("error-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.Anything).Return(
					nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Could not apply group policy",
		},
		{
			name: "creation with owner",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("admins"),
				Branch: types.StringValue("data/production"),
				Owner: &ConjurOwnerModel{
					Kind: types.StringValue("user"),
					ID:   types.StringValue("admin"),
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/production", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "group") && contains(content, "admins") && contains(content, "owner")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "creation with annotations",
			data: ConjurGroupResourceModel{
				Name:        types.StringValue("platform-team"),
				Branch:      types.StringValue("data/teams"),
				Annotations: map[string]string{"env": "prod", "department": "engineering"},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/teams", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "group") && contains(content, "platform-team")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "creation with owner and annotations",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("security-team"),
				Branch: types.StringValue("data/groups"),
				Owner: &ConjurOwnerModel{
					Kind: types.StringValue("group"),
					ID:   types.StringValue("managers"),
				},
				Annotations: map[string]string{"team": "security", "level": "critical"},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/groups", mock.Anything).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurGroupResource{
				client: mockV2,
			}

			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
				},
			}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
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

func TestGroupResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurGroupResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		shouldRemove  bool
		errorContains string
	}{
		{
			name: "group exists",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("developers"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RoleExists", "group:data/test/developers").Return(true, nil)
			},
			expectedError: false,
			shouldRemove:  false,
		},
		{
			name: "group not found - removes from state",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("missing-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RoleExists", "group:data/test/missing-group").Return(false, nil)
			},
			expectedError: false,
			shouldRemove:  true,
		},
		{
			name: "API error checking existence",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("error-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RoleExists", "group:data/test/error-group").
					Return(false, fmt.Errorf("connection error"))
			},
			expectedError: true,
			errorContains: "Unable to check if group",
		},
		{
			name: "nested branch group exists",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("admins"),
				Branch: types.StringValue("data/production/teams"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RoleExists", "group:data/production/teams/admins").Return(true, nil)
			},
			expectedError: false,
			shouldRemove:  false,
		},
		{
			name: "group with owner exists",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("security"),
				Branch: types.StringValue("data/groups"),
				Owner: &ConjurOwnerModel{
					Kind: types.StringValue("user"),
					ID:   types.StringValue("admin"),
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RoleExists", "group:data/groups/security").Return(true, nil)
			},
			expectedError: false,
			shouldRemove:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurGroupResource{
				client: mockV2,
			}

			req := resource.ReadRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
				},
			}
			resp := &resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
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

				if tt.shouldRemove {
					// State should be removed when group doesn't exist
					var result ConjurGroupResourceModel
					diag := resp.State.Get(ctx, &result)
					assert.True(t, diag.HasError() || result.Name.IsNull())
				} else {
					// State should still exist
					var result ConjurGroupResourceModel
					resp.State.Get(ctx, &result)
					assert.False(t, result.Name.IsNull())
					assert.Equal(t, tt.data.Name.ValueString(), result.Name.ValueString())
					assert.Equal(t, tt.data.Branch.ValueString(), result.Branch.ValueString())
				}
			}
			mockV2.AssertExpectations(t)
		})
	}
}

func TestGroupResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurGroupResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful deletion",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("developers"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "!delete") && contains(content, "developers")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during deletion",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("error-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.Anything).Return(
					nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Could not apply group deletion policy",
		},
		{
			name: "deletion from nested branch",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("admins"),
				Branch: types.StringValue("data/production/teams"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/production/teams", mock.MatchedBy(func(policy io.Reader) bool {
					buf := new(strings.Builder)
					_, _ = io.Copy(buf, policy)
					content := buf.String()
					return contains(content, "!delete") && contains(content, "admins")
				})).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "404 not found error",
			data: ConjurGroupResourceModel{
				Name:   types.StringValue("nonexistent-group"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/test", mock.Anything).Return(
					nil, fmt.Errorf("404 Not Found"))
			},
			expectedError: true,
			errorContains: "Could not apply group deletion policy",
		},
		{
			name: "deletion of group with annotations",
			data: ConjurGroupResourceModel{
				Name:        types.StringValue("platform-team"),
				Branch:      types.StringValue("data/teams"),
				Annotations: map[string]string{"env": "prod"},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy", conjurapi.PolicyModePatch, "data/teams", mock.Anything).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurGroupResource{
				client: mockV2,
			}

			req := resource.DeleteRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
				},
			}
			resp := &resource.DeleteResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getGroupTestSchema(),
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

func getGroupTestSchema() schema.Schema {
	r := &ConjurGroupResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
