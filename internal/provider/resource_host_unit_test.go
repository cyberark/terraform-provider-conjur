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

func TestHostResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurHostResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful creation with minimal fields",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("test-host"),
				Branch:       types.StringValue("data"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateWorkload", mock.MatchedBy(func(w conjurapi.Workload) bool {
					return w.Name == "test-host" && w.Branch == "data" && len(w.AuthnDescriptors) == 1
				})).Return([]byte{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during creation",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("error-host"),
				Branch:       types.StringValue("data"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateWorkload", mock.Anything).Return(nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to create host",
		},
		{
			name: "creation with all optional fields",
			data: ConjurHostResourceModel{
				Name:   types.StringValue("prod-host"),
				Branch: types.StringValue("data/production"),
				Type:   types.StringValue("jenkins"),
				Owner: &ConjurHostOwnerModel{
					Kind: types.StringValue("group"),
					ID:   types.StringValue("admins"),
				},
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type:      types.StringValue("jwt"),
						ServiceID: types.StringValue("jwt-service"),
						Data: &ConjurHostAuthnDescriptorData{
							Claims: map[string]string{"sub": "test", "aud": "myapp"},
						},
					},
				},
				Annotations: map[string]string{"env": "prod", "team": "platform"},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateWorkload", mock.MatchedBy(func(w conjurapi.Workload) bool {
					return w.Name == "prod-host" &&
						w.Branch == "data/production" &&
						w.Type == "jenkins" &&
						w.Owner != nil &&
						w.Owner.Kind == "group" &&
						w.Owner.Id == "admins" &&
						len(w.Annotations) == 2 &&
						len(w.AuthnDescriptors) == 1 &&
						w.AuthnDescriptors[0].ServiceID == "jwt-service"
				})).Return([]byte{}, nil)
			},
			expectedError: false,
		},
		{
			name: "creation with multiple authn descriptors",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("multi-auth-host"),
				Branch:       types.StringValue("data"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
					{
						Type:      types.StringValue("jwt"),
						ServiceID: types.StringValue("jwt-prod"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("CreateWorkload", mock.MatchedBy(func(w conjurapi.Workload) bool {
					return w.Name == "multi-auth-host" && len(w.AuthnDescriptors) == 2
				})).Return([]byte{}, nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurHostResource{
				client: mockV2,
			}

			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getHostTestSchema(),
				},
			}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getHostTestSchema(),
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
				var result ConjurHostResourceModel
				resp.State.Get(ctx, &result)
				assert.Equal(t, tt.data.Name.ValueString(), result.Name.ValueString())
				assert.Equal(t, tt.data.Branch.ValueString(), result.Branch.ValueString())
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func TestHostResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurHostResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		shouldRemove  bool
		errorContains string
	}{
		{
			name: "host exists",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("test-host"),
				Branch:       types.StringValue("data"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RoleExists", "host:data/test-host").Return(true, nil)
			},
			expectedError: false,
			shouldRemove:  false,
		},
		{
			name: "host not found - removes from state",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("missing-host"),
				Branch:       types.StringValue("data"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RoleExists", "host:data/missing-host").Return(false, nil)
			},
			expectedError: false,
			shouldRemove:  true,
		},
		{
			name: "API error checking existence",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("error-host"),
				Branch:       types.StringValue("data"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RoleExists", "host:data/error-host").
					Return(false, fmt.Errorf("connection error"))
			},
			expectedError: true,
			errorContains: "Unable to check if host",
		},
		{
			name: "nested branch path host exists",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("server-01"),
				Branch:       types.StringValue("data/production/servers"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("RoleExists", "host:data/production/servers/server-01").Return(true, nil)
			},
			expectedError: false,
			shouldRemove:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurHostResource{
				client: mockV2,
			}

			req := resource.ReadRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getHostTestSchema(),
				},
			}
			resp := &resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getHostTestSchema(),
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
					// State should be removed when host doesn't exist
					var result ConjurHostResourceModel
					diag := resp.State.Get(ctx, &result)
					assert.True(t, diag.HasError() || result.Name.IsNull())
				} else {
					// State should still exist
					var result ConjurHostResourceModel
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

func TestHostResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurHostResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful deletion",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("test-host"),
				Branch:       types.StringValue("data"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("DeleteWorkload", "data/test-host").Return([]byte{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during deletion",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("error-host"),
				Branch:       types.StringValue("data"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("DeleteWorkload", "data/error-host").
					Return(nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to delete host",
		},
		{
			name: "nested branch deletion",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("server-01"),
				Branch:       types.StringValue("data/production/servers"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("DeleteWorkload", "data/production/servers/server-01").Return([]byte{}, nil)
			},
			expectedError: false,
		},
		{
			name: "404 not found error",
			data: ConjurHostResourceModel{
				Name:         types.StringValue("nonexistent-host"),
				Branch:       types.StringValue("data"),
				RestrictedTo: types.ListNull(types.StringType),
				AuthnDescriptors: []ConjurHostAuthnDescriptor{
					{
						Type: types.StringValue("api_key"),
					},
				},
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("DeleteWorkload", "data/nonexistent-host").
					Return(nil, fmt.Errorf("404 Not Found"))
			},
			expectedError: true,
			errorContains: "Unable to delete host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurHostResource{
				client: mockV2,
			}

			req := resource.DeleteRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getHostTestSchema(),
				},
			}
			resp := &resource.DeleteResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getHostTestSchema(),
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

func getHostTestSchema() schema.Schema {
	r := &ConjurHostResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
