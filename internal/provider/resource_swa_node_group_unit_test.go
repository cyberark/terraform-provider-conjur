package provider

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
	swamocks "github.com/cyberark/terraform-provider-conjur/internal/swa/client/mocks"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func makeNodeGroupResponse(name string) *swaclient.NodeGroupResponse {
	return &swaclient.NodeGroupResponse{
		Name:                  name,
		WorkloadType:          "unix",
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
		WorkloadConfiguration: swaclient.WorkloadConfiguration{},
	}
}

func TestNodeGroupResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          NodeGroupResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful creation with minimal fields",
			data: NodeGroupResourceModel{
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				ng := makeNodeGroupResponse("prod-nodes")
				m.On("PostNodeGroupsWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostNodeGroupsJSONRequestBody{
					Name:         "prod-nodes",
					WorkloadType: "unix",
				}).Return(&swaclient.PostNodeGroupsResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: ng,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful creation with workload configuration",
			data: NodeGroupResourceModel{
				Name:            types.StringValue("k8s-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("k8s-servers"),
				WorkloadType:    types.StringValue("kubernetes"),
				Description:     types.StringNull(),
				WorkloadConfiguration: &WorkloadConfigurationModel{
					SpiffeIDTemplate:             types.StringValue("spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .k8s.ns }}/{{ .k8s.sa }}"),
					WorkloadRegistrationPolicies: types.ListNull(types.StringType),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				ng := makeNodeGroupResponse("k8s-nodes")
				ng.WorkloadType = "kubernetes"
				tmpl := "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .k8s.ns }}/{{ .k8s.sa }}"
				m.On("PostNodeGroupsWithResponse", context.Background(), "prod.example.org", "k8s-servers", &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostNodeGroupsJSONRequestBody{
					Name:         "k8s-nodes",
					WorkloadType: "kubernetes",
					WorkloadConfiguration: &swaclient.WorkloadConfiguration{
						SpiffeIdTemplate: &tmpl,
					},
				}).Return(&swaclient.PostNodeGroupsResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: ng,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during creation",
			data: NodeGroupResourceModel{
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostNodeGroupsWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostNodeGroupsJSONRequestBody{
					Name:         "prod-nodes",
					WorkloadType: "unix",
				}).Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error creating node group",
		},
		{
			name: "non-2xx status code",
			data: NodeGroupResourceModel{
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostNodeGroupsWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostNodeGroupsJSONRequestBody{
					Name:         "prod-nodes",
					WorkloadType: "unix",
				}).Return(&swaclient.PostNodeGroupsResponse{
					HTTPResponse: makeHTTPResponse(http.StatusConflict),
					Body:         []byte(`{"message":"already exists"}`),
				}, nil)
			},
			expectedError: true,
			errorContains: "Error creating node group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &NodeGroupResource{client: mockClient}

			req := resource.CreateRequest{
				Plan: newPlanWithSchema(getNodeGroupTestSchema()),
			}
			resp := &resource.CreateResponse{
				State: newStateWithSchema(getNodeGroupTestSchema()),
			}

			ctx := context.Background()
			if diags := req.Plan.Set(ctx, &tt.data); diags.HasError() {
				t.Fatalf("failed to set plan: %v", diags)
			}
			r.Create(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					assertDiagContains(t, resp.Diagnostics, tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
			}
		})
	}
}

func TestNodeGroupResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          NodeGroupResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		shouldRemove  bool
		errorContains string
		verify        func(t *testing.T, result NodeGroupResourceModel)
	}{
		{
			name: "successful read",
			data: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				ng := makeNodeGroupResponse("prod-nodes")
				m.On("GetNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetNodeGroupResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: ng,
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "not found removes from state",
			data: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/missing-nodes"),
				Name:            types.StringValue("missing-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "missing-nodes", &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetNodeGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNotFound),
					}, nil)
			},
			expectedError: false,
			shouldRemove:  true,
		},
		{
			name: "successful read with workload_configuration",
			data: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
				WorkloadConfiguration: &WorkloadConfigurationModel{
					SpiffeIDTemplate:             types.StringValue("spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .unix.user }}"),
					WorkloadRegistrationPolicies: types.ListNull(types.StringType),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				tmpl := "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .unix.user }}"
				ng := makeNodeGroupResponse("prod-nodes")
				ng.WorkloadConfiguration = swaclient.WorkloadConfiguration{SpiffeIdTemplate: &tmpl}
				m.On("GetNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetNodeGroupResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: ng,
					}, nil)
			},
			expectedError: false,
			verify: func(t *testing.T, result NodeGroupResourceModel) {
				require.NotNil(t, result.WorkloadConfiguration)
				assert.Equal(t, "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .unix.user }}", result.WorkloadConfiguration.SpiffeIDTemplate.ValueString())
			},
		},
		{
			name: "read with no workload_configuration on server keeps state nil",
			data: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				ng := makeNodeGroupResponse("prod-nodes")
				// WorkloadConfiguration is empty (no fields set)
				m.On("GetNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetNodeGroupResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: ng,
					}, nil)
			},
			expectedError: false,
			verify: func(t *testing.T, result NodeGroupResourceModel) {
				assert.Nil(t, result.WorkloadConfiguration, "workload_configuration should stay absent in state when the server reports none")
			},
		},
		{
			name: "API error during read",
			data: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(nil, fmt.Errorf("network error"))
			},
			expectedError: true,
			errorContains: "Error reading node group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &NodeGroupResource{client: mockClient}

			req := resource.ReadRequest{
				State: newStateWithSchema(getNodeGroupTestSchema()),
			}
			resp := &resource.ReadResponse{
				State: newStateWithSchema(getNodeGroupTestSchema()),
			}

			ctx := context.Background()
			if diags := req.State.Set(ctx, &tt.data); diags.HasError() {
				t.Fatalf("failed to set state: %v", diags)
			}
			r.Read(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					assertDiagContains(t, resp.Diagnostics, tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
				if tt.shouldRemove {
					assert.True(t, resp.State.Raw.IsNull(), "expected resource to be removed from state")
				} else if tt.verify != nil {
					var result NodeGroupResourceModel
					require.False(t, resp.State.Get(ctx, &result).HasError())
					tt.verify(t, result)
				}
			}
		})
	}
}

func TestNodeGroupResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          NodeGroupResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful deletion",
			data: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.DeleteNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteNodeGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNoContent),
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "deletion of already deleted resource (404)",
			data: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.DeleteNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteNodeGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNotFound),
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during deletion",
			data: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.DeleteNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error deleting node group",
		},
		{
			name: "non-success status code",
			data: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.DeleteNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteNodeGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusInternalServerError),
						Body:         []byte(`{"message":"internal error"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error deleting node group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &NodeGroupResource{client: mockClient}

			req := resource.DeleteRequest{
				State: newStateWithSchema(getNodeGroupTestSchema()),
			}
			resp := &resource.DeleteResponse{
				State: newStateWithSchema(getNodeGroupTestSchema()),
			}

			ctx := context.Background()
			if diags := req.State.Set(ctx, &tt.data); diags.HasError() {
				t.Fatalf("failed to set state: %v", diags)
			}
			r.Delete(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					assertDiagContains(t, resp.Diagnostics, tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
			}
		})
	}
}

func TestNodeGroupResource_Update(t *testing.T) {
	tests := []struct {
		name          string
		plan          NodeGroupResourceModel
		state         NodeGroupResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful update description",
			plan: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringValue("updated"),
			},
			state: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				ng := makeNodeGroupResponse("prod-nodes")
				desc := "updated"
				ng.Description = &desc
				m.On("PatchNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchNodeGroupJSONRequestBody{
					Description: &desc,
				}).Return(&swaclient.PatchNodeGroupResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: ng,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "update with workload configuration",
			plan: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
				WorkloadConfiguration: &WorkloadConfigurationModel{
					SpiffeIDTemplate:             types.StringValue("spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .unix.user }}"),
					WorkloadRegistrationPolicies: types.ListNull(types.StringType),
				},
			},
			state: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				ng := makeNodeGroupResponse("prod-nodes")
				tmpl := "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .unix.user }}"
				ng.WorkloadConfiguration = swaclient.WorkloadConfiguration{SpiffeIdTemplate: &tmpl}
				m.On("PatchNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchNodeGroupJSONRequestBody{
					WorkloadConfiguration: &swaclient.WorkloadConfiguration{SpiffeIdTemplate: &tmpl},
				}).Return(&swaclient.PatchNodeGroupResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: ng,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "remove workload_configuration resets to defaults",
			// plan has no workload_configuration; state previously had one → send empty object
			plan: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
				// WorkloadConfiguration intentionally absent
			},
			state: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
				WorkloadConfiguration: &WorkloadConfigurationModel{
					SpiffeIDTemplate:             types.StringValue("spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .unix.user }}"),
					WorkloadRegistrationPolicies: types.ListNull(types.StringType),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				ng := makeNodeGroupResponse("prod-nodes")
				// Server returns empty WorkloadConfiguration after reset
				m.On("PatchNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchNodeGroupJSONRequestBody{
					// Empty WorkloadConfiguration signals reset to defaults
					WorkloadConfiguration: &swaclient.WorkloadConfiguration{},
				}).Return(&swaclient.PatchNodeGroupResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: ng,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during update",
			plan: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			state: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchNodeGroupJSONRequestBody{}).
					Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error updating node group",
		},
		{
			name: "non-200 status code",
			plan: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			state: NodeGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers/prod-nodes"),
				Name:            types.StringValue("prod-nodes"),
				TrustDomainName: types.StringValue("prod.example.org"),
				ServerGroupName: types.StringValue("prod-servers"),
				WorkloadType:    types.StringValue("unix"),
				Description:     types.StringNull(),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchNodeGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", "prod-nodes", &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchNodeGroupJSONRequestBody{}).
					Return(&swaclient.PatchNodeGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusBadRequest),
						Body:         []byte(`{"message":"invalid input"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error updating node group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &NodeGroupResource{client: mockClient}

			req := resource.UpdateRequest{
				Plan:  newPlanWithSchema(getNodeGroupTestSchema()),
				State: newStateWithSchema(getNodeGroupTestSchema()),
			}
			resp := &resource.UpdateResponse{
				State: newStateWithSchema(getNodeGroupTestSchema()),
			}

			ctx := context.Background()
			if diags := req.Plan.Set(ctx, &tt.plan); diags.HasError() {
				t.Fatalf("failed to set plan: %v", diags)
			}
			if diags := req.State.Set(ctx, &tt.state); diags.HasError() {
				t.Fatalf("failed to set state: %v", diags)
			}
			r.Update(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					assertDiagContains(t, resp.Diagnostics, tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
			}
		})
	}
}

func TestNodeGroupResource_NilClientWarning(t *testing.T) {
	ctx := context.Background()
	s := getNodeGroupTestSchema()
	r := &NodeGroupResource{}

	t.Run("create", func(t *testing.T) {
		req := resource.CreateRequest{Plan: newPlanWithSchema(s)}
		resp := &resource.CreateResponse{State: newStateWithSchema(s)}

		r.Create(ctx, req, resp)

		assert.False(t, resp.Diagnostics.HasError())
		assertWarningContains(t, resp.Diagnostics, "Provider client not configured")
	})

	t.Run("read", func(t *testing.T) {
		req := resource.ReadRequest{State: newStateWithSchema(s)}
		resp := &resource.ReadResponse{State: newStateWithSchema(s)}

		r.Read(ctx, req, resp)

		assert.False(t, resp.Diagnostics.HasError())
		assertWarningContains(t, resp.Diagnostics, "Provider client not configured")
	})

	t.Run("update", func(t *testing.T) {
		req := resource.UpdateRequest{Plan: newPlanWithSchema(s), State: newStateWithSchema(s)}
		resp := &resource.UpdateResponse{State: newStateWithSchema(s)}

		r.Update(ctx, req, resp)

		assert.False(t, resp.Diagnostics.HasError())
		assertWarningContains(t, resp.Diagnostics, "Provider client not configured")
	})

	t.Run("delete", func(t *testing.T) {
		req := resource.DeleteRequest{State: newStateWithSchema(s)}
		resp := &resource.DeleteResponse{State: newStateWithSchema(s)}

		r.Delete(ctx, req, resp)

		assert.False(t, resp.Diagnostics.HasError())
		assertWarningContains(t, resp.Diagnostics, "Provider client not configured")
	})
}

func TestNodeGroupResource_ImportState(t *testing.T) {
	ctx := context.Background()
	r := &NodeGroupResource{}
	s := getNodeGroupTestSchema()

	t.Run("passthrough import by id", func(t *testing.T) {
		req := resource.ImportStateRequest{ID: "prod.example.org/prod-servers/prod-nodes"}
		resp := &resource.ImportStateResponse{
			State: newStateWithSchema(s),
		}
		r.ImportState(ctx, req, resp)
		require.False(t, resp.Diagnostics.HasError())

		var result NodeGroupResourceModel
		resp.State.Get(ctx, &result)
		assert.Equal(t, "prod.example.org/prod-servers/prod-nodes", result.ID.ValueString())
		assert.Equal(t, "prod.example.org", result.TrustDomainName.ValueString())
		assert.Equal(t, "prod-servers", result.ServerGroupName.ValueString())
		assert.Equal(t, "prod-nodes", result.Name.ValueString())
	})

	t.Run("invalid import id", func(t *testing.T) {
		req := resource.ImportStateRequest{ID: "prod.example.org/prod-servers"}
		resp := &resource.ImportStateResponse{
			State: newStateWithSchema(s),
		}
		r.ImportState(ctx, req, resp)
		assert.True(t, resp.Diagnostics.HasError())
		assertDiagContains(t, resp.Diagnostics, "Invalid Import ID")
	})
}

// TestNodeGroupResource_WorkloadRegistrationPoliciesRoundTrip exercises the
// non-null path of workload_registration_policies end-to-end: converting the
// plan list to the API request (buildWorkloadConfiguration) and converting a
// populated API response back into state (syncWorkloadConfigFromResponse).
// Other tests only ever exercise the null-list case for this field.
func TestNodeGroupResource_WorkloadRegistrationPoliciesRoundTrip(t *testing.T) {
	ctx := context.Background()
	policies := []string{
		"attestation.selectors['unix:uid'] == '1000'",
		"attestation.selectors['unix:user'] == 'app'",
	}
	policyList, diags := types.ListValueFrom(ctx, types.StringType, policies)
	require.False(t, diags.HasError())

	ng := makeNodeGroupResponse("prod-nodes")
	ng.WorkloadConfiguration = swaclient.WorkloadConfiguration{WorkloadRegistrationPolicies: &policies}

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)
	mockClient.On("PostNodeGroupsWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostNodeGroupsJSONRequestBody{
		Name:         "prod-nodes",
		WorkloadType: "unix",
		WorkloadConfiguration: &swaclient.WorkloadConfiguration{
			WorkloadRegistrationPolicies: &policies,
		},
	}).Return(&swaclient.PostNodeGroupsResponse{
		HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
		ApplicationxSecretsmgrV2JSON201: ng,
	}, nil)

	r := &NodeGroupResource{client: mockClient}
	req := resource.CreateRequest{Plan: newPlanWithSchema(getNodeGroupTestSchema())}
	resp := &resource.CreateResponse{State: newStateWithSchema(getNodeGroupTestSchema())}

	data := NodeGroupResourceModel{
		Name:            types.StringValue("prod-nodes"),
		TrustDomainName: types.StringValue("prod.example.org"),
		ServerGroupName: types.StringValue("prod-servers"),
		WorkloadType:    types.StringValue("unix"),
		Description:     types.StringNull(),
		WorkloadConfiguration: &WorkloadConfigurationModel{
			SpiffeIDTemplate:             types.StringNull(),
			WorkloadRegistrationPolicies: policyList,
		},
	}
	require.False(t, req.Plan.Set(ctx, &data).HasError())

	r.Create(ctx, req, resp)
	require.False(t, resp.Diagnostics.HasError())

	var result NodeGroupResourceModel
	require.False(t, resp.State.Get(ctx, &result).HasError())
	require.NotNil(t, result.WorkloadConfiguration)

	var gotPolicies []string
	require.False(t, result.WorkloadConfiguration.WorkloadRegistrationPolicies.ElementsAs(ctx, &gotPolicies, false).HasError())
	assert.Equal(t, policies, gotPolicies)
}

func getNodeGroupTestSchema() schema.Schema {
	r := &NodeGroupResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}

// --- Schema plan modifier tests ---

func TestNodeGroupResource_Schema_RequiresReplace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &NodeGroupResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	tests := []struct {
		attrPath      string
		shouldReplace bool
	}{
		{"name", true},
		{"trust_domain_name", true},
		{"server_group_name", true},
		{"workload_type", true},
		{"id", false},
		{"description", false},
		{"workload_configuration", false},
	}

	const requiresReplaceDesc = "If the value of this attribute changes, Terraform will destroy and recreate the resource."

	for _, tc := range tests {
		t.Run(tc.attrPath, func(t *testing.T) {
			t.Parallel()
			attr := schemaResp.Schema.Attributes[tc.attrPath]
			assert.NotNil(t, attr, "attribute %q not found in schema", tc.attrPath)

			hasRequiresReplace := false
			switch a := attr.(type) {
			case schema.StringAttribute:
				for _, pm := range a.PlanModifiers {
					if pm.Description(ctx) == requiresReplaceDesc {
						hasRequiresReplace = true
					}
				}
			case schema.SingleNestedAttribute:
				for _, pm := range a.PlanModifiers {
					if pm.Description(ctx) == requiresReplaceDesc {
						hasRequiresReplace = true
					}
				}
			}

			if tc.shouldReplace {
				assert.True(t, hasRequiresReplace, "attribute %q should have RequiresReplace", tc.attrPath)
			} else {
				assert.False(t, hasRequiresReplace, "attribute %q should NOT have RequiresReplace", tc.attrPath)
			}
		})
	}
}

// --- Lifecycle tests (mock-client acceptance style) ---

func TestNodeGroupResource_CreateAndDelete(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)
	now := time.Now()

	mockClient.EXPECT().
		PostNodeGroupsWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything, mock.Anything).
		Return(&swaclient.PostNodeGroupsResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.NodeGroupResponse{
				Name: "test-ng", WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{},
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.GetNodeGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.NodeGroupResponse{
				Name: "test-ng", WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.DeleteNodeGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_node_group" "test" {
  name              = "test-ng"
  trust_domain_name = "test-td"
  server_group_name = "test-sg"
  workload_type     = "unix"
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "name", "test-ng"),
					tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "id", "test-td/test-sg/test-ng"),
					tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "workload_type", "unix"),
				),
			},
		},
	})
}

func TestNodeGroupResource_WorkloadTypeChange_RequiresReplace(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)
	now := time.Now()

	mockClient.EXPECT().
		PostNodeGroupsWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything,
			mock.MatchedBy(func(body swaclient.PostNodeGroupsJSONRequestBody) bool { return body.WorkloadType == "unix" })).
		Return(&swaclient.PostNodeGroupsResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.NodeGroupResponse{
				Name: "test-ng", WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{},
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		PostNodeGroupsWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything,
			mock.MatchedBy(func(body swaclient.PostNodeGroupsJSONRequestBody) bool { return body.WorkloadType == "kubernetes" })).
		Return(&swaclient.PostNodeGroupsResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.NodeGroupResponse{
				Name: "test-ng", WorkloadType: "kubernetes", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{},
			},
		}, nil).Times(1)

	// Read returns unix for the post-create read and the step-2 refresh so
	// Terraform detects the workload_type diff and triggers RequiresReplace.
	mockClient.EXPECT().
		GetNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.GetNodeGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.NodeGroupResponse{
				Name: "test-ng", WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{},
			},
		}, nil).Times(2)

	// Read after replacement returns kubernetes.
	mockClient.EXPECT().
		GetNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.GetNodeGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.NodeGroupResponse{
				Name: "test-ng", WorkloadType: "kubernetes", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{},
			},
		}, nil).Maybe()

	// Delete unix during replace + final delete of kubernetes.
	mockClient.EXPECT().
		DeleteNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.DeleteNodeGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(2)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_node_group" "test" {
  name              = "test-ng"
  trust_domain_name = "test-td"
  server_group_name = "test-sg"
  workload_type     = "unix"
}
`,
				Check: tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "workload_type", "unix"),
			},
			{
				// Changing workload_type must trigger destroy+create, not update.
				Config: `
resource "conjur_swa_node_group" "test" {
  name              = "test-ng"
  trust_domain_name = "test-td"
  server_group_name = "test-sg"
  workload_type     = "kubernetes"
}
`,
				Check: tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "workload_type", "kubernetes"),
			},
		},
	})
}

func TestNodeGroupResource_ClearWorkloadConfiguration(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)
	now := time.Now()

	customTemplate := "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/custom/{{ .unix.user }}"
	policies := []string{"unix.uid == 1000"}

	mockClient.EXPECT().
		PostNodeGroupsWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything, mock.Anything).
		Return(&swaclient.PostNodeGroupsResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.NodeGroupResponse{
				Name: "test-ng", WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{
					SpiffeIdTemplate:             &customTemplate,
					WorkloadRegistrationPolicies: &policies,
				},
			},
		}, nil).Times(1)

	// Read after create AND the pre-plan refresh before step-2 — both must return
	// the custom config so the step-2 plan sees a diff and calls Update/Patch.
	mockClient.EXPECT().
		GetNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.GetNodeGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.NodeGroupResponse{
				Name: "test-ng", WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{
					SpiffeIdTemplate:             &customTemplate,
					WorkloadRegistrationPolicies: &policies,
				},
			},
		}, nil).Times(2)

	// Patch clears workload_configuration (non-nil body with nil fields).
	mockClient.EXPECT().
		PatchNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything, mock.Anything).
		Return(&swaclient.PatchNodeGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			// Both fields nil so syncWorkloadConfigFromResponse sets WorkloadConfiguration = nil,
			// matching the step-2 config that omits the workload_configuration block.
			ApplicationxSecretsmgrV2JSON200: &swaclient.NodeGroupResponse{
				Name: "test-ng", WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{},
			},
		}, nil).Times(1)

	// Read after clear: all-nil WorkloadConfiguration keeps the block absent in state.
	mockClient.EXPECT().
		GetNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.GetNodeGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.NodeGroupResponse{
				Name: "test-ng", WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.DeleteNodeGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_node_group" "test" {
  name              = "test-ng"
  trust_domain_name = "test-td"
  server_group_name = "test-sg"
  workload_type     = "unix"
  workload_configuration = {
    spiffe_id_template             = "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/custom/{{ .unix.user }}"
    workload_registration_policies = ["unix.uid == 1000"]
  }
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "workload_configuration.spiffe_id_template", customTemplate),
					tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "workload_configuration.workload_registration_policies.#", "1"),
				),
			},
			{
				// Remove workload_configuration entirely — triggers the clear path.
				Config: `
resource "conjur_swa_node_group" "test" {
  name              = "test-ng"
  trust_domain_name = "test-td"
  server_group_name = "test-sg"
  workload_type     = "unix"
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "name", "test-ng"),
					tfresource.TestCheckNoResourceAttr("conjur_swa_node_group.test", "workload_configuration.spiffe_id_template"),
					tfresource.TestCheckNoResourceAttr("conjur_swa_node_group.test", "workload_configuration.workload_registration_policies.#"),
				),
			},
		},
	})
}

func TestNodeGroupResource_InPlaceUpdate_DescriptionAndWorkloadConfig(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)
	now := time.Now()

	updatedTemplate := "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/custom/{{ .unix.uid }}"
	originalDesc := "original description"
	updatedDesc := "updated description"
	policies := []string{"unix.uid > 500"}

	mockClient.EXPECT().
		PostNodeGroupsWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything, mock.Anything).
		Return(&swaclient.PostNodeGroupsResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			// Step-1 config has no workload_configuration block, so the Create response
			// must also return an empty WorkloadConfiguration to avoid a consistency error.
			ApplicationxSecretsmgrV2JSON201: &swaclient.NodeGroupResponse{
				Name: "test-ng", Description: &originalDesc, WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{},
			},
		}, nil).Times(1)

	// Read after create AND the pre-plan refresh before step-2 — both must return
	// empty WorkloadConfiguration so the step-2 plan sees nil→non-nil diff and calls Update/Patch.
	mockClient.EXPECT().
		GetNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.GetNodeGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.NodeGroupResponse{
				Name: "test-ng", Description: &originalDesc, WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{},
			},
		}, nil).Times(2)

	// Patch with updated description + workload_configuration.
	mockClient.EXPECT().
		PatchNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything,
			mock.MatchedBy(func(body swaclient.PatchNodeGroupJSONRequestBody) bool {
				return body.Description != nil && *body.Description == updatedDesc &&
					body.WorkloadConfiguration != nil &&
					body.WorkloadConfiguration.SpiffeIdTemplate != nil && *body.WorkloadConfiguration.SpiffeIdTemplate == updatedTemplate &&
					body.WorkloadConfiguration.WorkloadRegistrationPolicies != nil
			})).
		Return(&swaclient.PatchNodeGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.NodeGroupResponse{
				Name: "test-ng", Description: &updatedDesc, WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{
					SpiffeIdTemplate:             &updatedTemplate,
					WorkloadRegistrationPolicies: &policies,
				},
			},
		}, nil).Times(1)

	// Read after update.
	mockClient.EXPECT().
		GetNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.GetNodeGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.NodeGroupResponse{
				Name: "test-ng", Description: &updatedDesc, WorkloadType: "unix", CreatedAt: now, UpdatedAt: now,
				WorkloadConfiguration: swaclient.WorkloadConfiguration{
					SpiffeIdTemplate:             &updatedTemplate,
					WorkloadRegistrationPolicies: &policies,
				},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteNodeGroupWithResponse(mock.Anything, "test-td", "test-sg", "test-ng", mock.Anything).
		Return(&swaclient.DeleteNodeGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_node_group" "test" {
  name              = "test-ng"
  trust_domain_name = "test-td"
  server_group_name = "test-sg"
  workload_type     = "unix"
  description       = "original description"
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "description", originalDesc),
					tfresource.TestCheckNoResourceAttr("conjur_swa_node_group.test", "workload_configuration.spiffe_id_template"),
				),
			},
			{
				Config: `
resource "conjur_swa_node_group" "test" {
  name              = "test-ng"
  trust_domain_name = "test-td"
  server_group_name = "test-sg"
  workload_type     = "unix"
  description       = "updated description"
  workload_configuration = {
    spiffe_id_template             = "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/custom/{{ .unix.uid }}"
    workload_registration_policies = ["unix.uid > 500"]
  }
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "description", updatedDesc),
					tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "workload_configuration.spiffe_id_template", updatedTemplate),
					tfresource.TestCheckResourceAttr("conjur_swa_node_group.test", "workload_configuration.workload_registration_policies.#", "1"),
				),
			},
		},
	})
}
