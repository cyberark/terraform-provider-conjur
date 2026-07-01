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
	"github.com/stretchr/testify/assert"
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
				m.On("PostNodeGroupsWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostNodeGroupsJSONRequestBody{
					Name:         "prod-nodes",
					WorkloadType: swaclient.NodeGroupCreateRequestWorkloadType("unix"),
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
				m.On("PostNodeGroupsWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("k8s-servers"), &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostNodeGroupsJSONRequestBody{
					Name:         "k8s-nodes",
					WorkloadType: swaclient.NodeGroupCreateRequestWorkloadType("kubernetes"),
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
				m.On("PostNodeGroupsWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostNodeGroupsJSONRequestBody{
					Name:         "prod-nodes",
					WorkloadType: swaclient.NodeGroupCreateRequestWorkloadType("unix"),
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
				m.On("PostNodeGroupsWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostNodeGroupsJSONRequestBody{
					Name:         "prod-nodes",
					WorkloadType: swaclient.NodeGroupCreateRequestWorkloadType("unix"),
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
				m.On("GetNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("GetNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("missing-nodes"), &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("GetNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetNodeGroupResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: ng,
					}, nil)
			},
			expectedError: false,
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
				m.On("GetNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetNodeGroupResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: ng,
					}, nil)
			},
			expectedError: false,
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
				m.On("GetNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.GetNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("DeleteNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.DeleteNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("DeleteNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.DeleteNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("DeleteNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.DeleteNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("DeleteNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.DeleteNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("PatchNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchNodeGroupJSONRequestBody{
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
				m.On("PatchNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchNodeGroupJSONRequestBody{
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
				m.On("PatchNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchNodeGroupJSONRequestBody{
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
				m.On("PatchNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchNodeGroupJSONRequestBody{}).
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
				m.On("PatchNodeGroupWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.NodeGroupName("prod-nodes"), &swaclient.PatchNodeGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchNodeGroupJSONRequestBody{}).
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
	mockClient.On("PostNodeGroupsWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostNodeGroupsParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostNodeGroupsJSONRequestBody{
		Name:         "prod-nodes",
		WorkloadType: swaclient.NodeGroupCreateRequestWorkloadType("unix"),
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
