package provider

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
	swamocks "github.com/cyberark/terraform-provider-conjur/internal/swa/client/mocks"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func mustClustersMap(t *testing.T, ctx context.Context, clusters map[string]K8sPsatClusterModel) types.Map {
	t.Helper()
	objs := make(map[string]attr.Value, len(clusters))
	for k, v := range clusters {
		obj, diags := types.ObjectValueFrom(ctx, k8sPsatClusterAttrTypes(), v)
		require.False(t, diags.HasError(), "failed to build cluster object: %v", diags)
		objs[k] = obj
	}
	m, diags := types.MapValue(types.ObjectType{AttrTypes: k8sPsatClusterAttrTypes()}, objs)
	require.False(t, diags.HasError(), "failed to build clusters map: %v", diags)
	return m
}

func makeServerGroupResponse(name, trustDomain string) *swaclient.ServerGroupResponse {
	now := time.Now()
	return &swaclient.ServerGroupResponse{
		Name:            name,
		TrustDomainName: trustDomain,
		CreatedAt:       &now,
		UpdatedAt:       &now,
	}
}

// TestUpdateNodeAttestationFromResponse verifies that updateNodeAttestationFromResponse fully
// reconciles state from the API response (rather than merging into whatever was already in the
// model), so attestation methods or clusters removed server-side actually disappear from state
// on the next Read instead of persisting indefinitely.
func TestUpdateNodeAttestationFromResponse(t *testing.T) {
	ctx := context.Background()

	mustStringList := func(t *testing.T, values ...string) types.List {
		t.Helper()
		list, diags := types.ListValueFrom(ctx, types.StringType, values)
		require.False(t, diags.HasError(), "failed to build test list: %v", diags)
		return list
	}

	t.Run("nil response clears node attestation", func(t *testing.T) {
		model := &ServerGroupResourceModel{
			NodeAttestation: &NodeAttestationModel{
				X509Pop: &X509PopModel{CaCertificates: types.StringValue("stale-cert")},
			},
		}
		diags := updateNodeAttestationFromResponse(ctx, model, nil)
		assert.False(t, diags.HasError())
		assert.Nil(t, model.NodeAttestation)
	})

	t.Run("x509pop removed server-side is removed from state", func(t *testing.T) {
		model := &ServerGroupResourceModel{
			NodeAttestation: &NodeAttestationModel{
				X509Pop: &X509PopModel{CaCertificates: types.StringValue("stale-cert")},
			},
		}
		na := &struct {
			K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
			X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
		}{
			K8sPsat: &swaclient.K8sPsatConfigurationInput{
				Clusters: &map[string]swaclient.K8sPsatCluster{
					"cluster-a": {},
				},
			},
		}

		diags := updateNodeAttestationFromResponse(ctx, model, na)
		assert.False(t, diags.HasError())
		require.NotNil(t, model.NodeAttestation)
		assert.Nil(t, model.NodeAttestation.X509Pop, "x509pop should be cleared once the server no longer reports it")
		require.NotNil(t, model.NodeAttestation.K8sPsat)
		assert.True(t, model.NodeAttestation.K8sPsat.Clusters.Elements() != nil)
		assert.Contains(t, model.NodeAttestation.K8sPsat.Clusters.Elements(), "cluster-a")
	})

	t.Run("cluster removed server-side is removed from state", func(t *testing.T) {
		nullLists := K8sPsatClusterModel{
			ServiceAccountAllowList: types.ListNull(types.StringType),
			Audience:                types.ListNull(types.StringType),
			AllowedPodLabelKeys:     types.ListNull(types.StringType),
			AllowedNodeLabelKeys:    types.ListNull(types.StringType),
		}
		clusterA := nullLists
		clusterA.ServiceAccountAllowList = mustStringList(t, "ns/sa")
		clusterB := nullLists
		clusterB.ServiceAccountAllowList = mustStringList(t, "ns2/sa2")
		model := &ServerGroupResourceModel{
			NodeAttestation: &NodeAttestationModel{
				K8sPsat: &K8sPsatModel{
					Clusters: mustClustersMap(t, ctx, map[string]K8sPsatClusterModel{
						"cluster-a": clusterA,
						"cluster-b": clusterB,
					}),
				},
			},
		}
		na := &struct {
			K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
			X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
		}{
			K8sPsat: &swaclient.K8sPsatConfigurationInput{
				Clusters: &map[string]swaclient.K8sPsatCluster{
					"cluster-a": {},
				},
			},
		}

		diags := updateNodeAttestationFromResponse(ctx, model, na)
		assert.False(t, diags.HasError())
		require.NotNil(t, model.NodeAttestation.K8sPsat)
		assert.Contains(t, model.NodeAttestation.K8sPsat.Clusters.Elements(), "cluster-a")
		assert.NotContains(t, model.NodeAttestation.K8sPsat.Clusters.Elements(), "cluster-b", "cluster-b was removed server-side and must not persist in state")
	})

	t.Run("k8s_psat removed server-side is removed from state", func(t *testing.T) {
		emptyCluster := K8sPsatClusterModel{
			ServiceAccountAllowList: types.ListNull(types.StringType),
			Audience:                types.ListNull(types.StringType),
			AllowedPodLabelKeys:     types.ListNull(types.StringType),
			AllowedNodeLabelKeys:    types.ListNull(types.StringType),
		}
		model := &ServerGroupResourceModel{
			NodeAttestation: &NodeAttestationModel{
				X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				K8sPsat: &K8sPsatModel{
					Clusters: mustClustersMap(t, ctx, map[string]K8sPsatClusterModel{
						"cluster-a": emptyCluster,
					}),
				},
			},
		}
		na := &struct {
			K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
			X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
		}{
			X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "cert"},
		}

		diags := updateNodeAttestationFromResponse(ctx, model, na)
		assert.False(t, diags.HasError())
		require.NotNil(t, model.NodeAttestation)
		assert.Nil(t, model.NodeAttestation.K8sPsat, "k8s_psat should be cleared once the server no longer reports it")
	})
}

func TestBuildK8sPsatClusters(t *testing.T) {
	ctx := context.Background()

	mustStringList := func(t *testing.T, values ...string) types.List {
		t.Helper()
		list, diags := types.ListValueFrom(ctx, types.StringType, values)
		require.False(t, diags.HasError(), "failed to build test list: %v", diags)
		return list
	}

	t.Run("nil model returns nil map", func(t *testing.T) {
		clusters, diags := buildK8sPsatClusters(ctx, nil)
		require.Nil(t, clusters)
		assert.False(t, diags.HasError())
	})

	t.Run("null clusters returns nil map", func(t *testing.T) {
		clusters, diags := buildK8sPsatClusters(ctx, &K8sPsatModel{
			Clusters: types.MapNull(types.ObjectType{AttrTypes: k8sPsatClusterAttrTypes()}),
		})
		require.Nil(t, clusters)
		assert.False(t, diags.HasError())
	})

	t.Run("converts non-null list attributes", func(t *testing.T) {
		clusters, diags := buildK8sPsatClusters(ctx, &K8sPsatModel{
			Clusters: mustClustersMap(t, ctx, map[string]K8sPsatClusterModel{
				"cluster-a": {
					ServiceAccountAllowList: mustStringList(t, "ns1/sa1", "ns2/sa2"),
					Audience:                mustStringList(t, "audience-a"),
					AllowedPodLabelKeys:     mustStringList(t, "team", "app"),
					AllowedNodeLabelKeys:    mustStringList(t, "kubernetes.io/hostname"),
				},
			}),
		})

		require.False(t, diags.HasError())
		require.Len(t, clusters, 1)

		cluster := clusters["cluster-a"]
		require.NotNil(t, cluster.ServiceAccountAllowList)
		require.NotNil(t, cluster.Audience)
		require.NotNil(t, cluster.AllowedPodLabelKeys)
		require.NotNil(t, cluster.AllowedNodeLabelKeys)

		assert.Equal(t, []string{"ns1/sa1", "ns2/sa2"}, *cluster.ServiceAccountAllowList)
		assert.Equal(t, []string{"audience-a"}, *cluster.Audience)
		assert.Equal(t, []string{"team", "app"}, *cluster.AllowedPodLabelKeys)
		assert.Equal(t, []string{"kubernetes.io/hostname"}, *cluster.AllowedNodeLabelKeys)
	})

	t.Run("null list attributes are omitted", func(t *testing.T) {
		clusters, diags := buildK8sPsatClusters(ctx, &K8sPsatModel{
			Clusters: mustClustersMap(t, ctx, map[string]K8sPsatClusterModel{
				"cluster-a": {
					ServiceAccountAllowList: types.ListNull(types.StringType),
					Audience:                types.ListNull(types.StringType),
					AllowedPodLabelKeys:     types.ListNull(types.StringType),
					AllowedNodeLabelKeys:    types.ListNull(types.StringType),
				},
			}),
		})

		require.False(t, diags.HasError())
		require.Len(t, clusters, 1)

		cluster := clusters["cluster-a"]
		assert.Nil(t, cluster.ServiceAccountAllowList)
		assert.Nil(t, cluster.Audience)
		assert.Nil(t, cluster.AllowedPodLabelKeys)
		assert.Nil(t, cluster.AllowedNodeLabelKeys)
	})

	t.Run("unknown list reports diagnostics", func(t *testing.T) {
		attrTypes := k8sPsatClusterAttrTypes()
		obj, diags := types.ObjectValue(attrTypes, map[string]attr.Value{
			"service_account_allow_list": types.ListNull(types.StringType),
			"audience":                   types.ListUnknown(types.StringType),
			"allowed_pod_label_keys":     types.ListNull(types.StringType),
			"allowed_node_label_keys":    types.ListNull(types.StringType),
		})
		require.False(t, diags.HasError())
		clustersMap, diags := types.MapValue(types.ObjectType{AttrTypes: attrTypes}, map[string]attr.Value{"cluster-a": obj})
		require.False(t, diags.HasError())

		_, diags = buildK8sPsatClusters(ctx, &K8sPsatModel{Clusters: clustersMap})
		assert.True(t, diags.HasError())
	})
}

func TestServerGroupResource_ValidateConfig(t *testing.T) {
	tests := []struct {
		name          string
		data          ServerGroupResourceModel
		expectedError bool
		errorContains string
	}{
		{
			name: "valid with x509pop",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			expectedError: false,
		},
		{
			name: "invalid without x509pop and k8s_psat",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{},
			},
			expectedError: true,
			errorContains: "Invalid node_attestation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ServerGroupResource{}
			req := resource.ValidateConfigRequest{Config: buildServerGroupConfigFromModel(tt.data)}
			resp := &resource.ValidateConfigResponse{}

			r.ValidateConfig(context.Background(), req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				assertDiagContains(t, resp.Diagnostics, tt.errorContains)
			} else {
				assert.False(t, resp.Diagnostics.HasError())
			}
		})
	}
}

func TestServerGroupResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          ServerGroupResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful creation with X509PoP attestation",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name: "prod-servers",
					NodeAttestation: struct {
						K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
						X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
					}{
						X509pop: &swaclient.X509PopConfigurationInput{
							CaCertificates: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
						},
					},
				}).Return(&swaclient.PostServerGroupResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: sg,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful creation with description",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringValue("Production servers"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				desc := "Production servers"
				sg.Description = &desc
				descPtr := "Production servers"
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name:        "prod-servers",
					Description: &descPtr,
					NodeAttestation: struct {
						K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
						X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
					}{
						X509pop: &swaclient.X509PopConfigurationInput{
							CaCertificates: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
						},
					},
				}).Return(&swaclient.PostServerGroupResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: sg,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "missing node_attestation block",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Missing node attestation",
		},
		{
			name: "node_attestation with neither x509pop nor k8s_psat",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Missing node attestation",
		},
		{
			name: "API error during creation",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("cert"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name: "prod-servers",
					NodeAttestation: struct {
						K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
						X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
					}{
						X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "cert"},
					},
				}).Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error creating server group",
		},
		{
			name: "non-2xx status code",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("cert"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name: "prod-servers",
					NodeAttestation: struct {
						K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
						X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
					}{
						X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "cert"},
					},
				}).Return(&swaclient.PostServerGroupResponse{
					HTTPResponse: makeHTTPResponse(http.StatusConflict),
					Body:         []byte(`{"message":"already exists"}`),
				}, nil)
			},
			expectedError: true,
			errorContains: "Error creating server group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &ServerGroupResource{client: mockClient}

			req := resource.CreateRequest{
				Plan: newPlanWithSchema(getServerGroupTestSchema()),
			}
			resp := &resource.CreateResponse{
				State: newStateWithSchema(getServerGroupTestSchema()),
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

func TestServerGroupResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          ServerGroupResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		shouldRemove  bool
		expectedCert  string
		errorContains string
	}{
		{
			name: "successful read syncs node attestation",
			data: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("stale-cert"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				sg.NodeAttestation = &struct {
					K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
					X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
				}{
					X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "fresh-cert"},
				}
				m.On("GetServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.GetServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetServerGroupResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: sg,
					}, nil)
			},
			expectedError: false,
			expectedCert:  "fresh-cert",
		},
		{
			name: "read hydrates node attestation when missing from state",
			data: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				sg.NodeAttestation = &struct {
					K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
					X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
				}{
					X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "fresh-cert"},
				}
				m.On("GetServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.GetServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetServerGroupResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: sg,
					}, nil)
			},
			expectedError: false,
			expectedCert:  "fresh-cert",
		},
		{
			name: "not found removes from state",
			data: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/missing-servers"),
				Name:            types.StringValue("missing-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("cert"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetServerGroupWithResponse", context.Background(), "prod.example.org", "missing-servers", &swaclient.GetServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetServerGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNotFound),
					}, nil)
			},
			expectedError: false,
			shouldRemove:  true,
		},
		{
			name: "non-200 status code during read",
			data: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.GetServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetServerGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusInternalServerError),
						Body:         []byte(`{"message":"internal error"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error reading server group",
		},
		{
			name: "API error during read",
			data: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("cert"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.GetServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(nil, fmt.Errorf("network error"))
			},
			expectedError: true,
			errorContains: "Error reading server group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &ServerGroupResource{client: mockClient}

			req := resource.ReadRequest{
				State: newStateWithSchema(getServerGroupTestSchema()),
			}
			resp := &resource.ReadResponse{
				State: newStateWithSchema(getServerGroupTestSchema()),
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
				} else if tt.expectedCert != "" {
					var result ServerGroupResourceModel
					diag := resp.State.Get(ctx, &result)
					require.False(t, diag.HasError())
					require.NotNil(t, result.NodeAttestation)
					require.NotNil(t, result.NodeAttestation.X509Pop)
					assert.Equal(t, tt.expectedCert, result.NodeAttestation.X509Pop.CaCertificates.ValueString())
				}
			}
		})
	}
}

func TestServerGroupResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          ServerGroupResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful deletion",
			data: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.DeleteServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteServerGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNoContent),
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "deletion of already deleted resource (404)",
			data: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.DeleteServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteServerGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNotFound),
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during deletion",
			data: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.DeleteServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error deleting server group",
		},
		{
			name: "non-success status code",
			data: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.DeleteServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteServerGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusInternalServerError),
						Body:         []byte(`{"message":"internal error"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error deleting server group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &ServerGroupResource{client: mockClient}

			req := resource.DeleteRequest{
				State: newStateWithSchema(getServerGroupTestSchema()),
			}
			resp := &resource.DeleteResponse{
				State: newStateWithSchema(getServerGroupTestSchema()),
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

func TestServerGroupResource_Update(t *testing.T) {
	tests := []struct {
		name          string
		plan          ServerGroupResourceModel
		state         ServerGroupResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful update description",
			plan: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringValue("updated description"),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				desc := "updated description"
				sg.Description = &desc
				m.On("PatchServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PatchServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchServerGroupJSONRequestBody{
					Description: &desc,
					NodeAttestation: &struct {
						K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
						X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
					}{
						X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "cert"},
					},
				}).Return(&swaclient.PatchServerGroupResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: sg,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during update",
			plan: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PatchServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchServerGroupJSONRequestBody{
					NodeAttestation: &struct {
						K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
						X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
					}{
						X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "cert"},
					},
				}).Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error updating server group",
		},
		{
			name: "missing node_attestation block",
			plan: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Missing node attestation",
		},
		{
			name: "non-200 status code",
			plan: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				NodeAttestation: &NodeAttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PatchServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchServerGroupJSONRequestBody{
					NodeAttestation: &struct {
						K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
						X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
					}{
						X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "cert"},
					},
				}).Return(&swaclient.PatchServerGroupResponse{
					HTTPResponse: makeHTTPResponse(http.StatusBadRequest),
					Body:         []byte(`{"message":"invalid input"}`),
				}, nil)
			},
			expectedError: true,
			errorContains: "Error updating server group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &ServerGroupResource{client: mockClient}

			req := resource.UpdateRequest{
				Plan:  newPlanWithSchema(getServerGroupTestSchema()),
				State: newStateWithSchema(getServerGroupTestSchema()),
			}
			resp := &resource.UpdateResponse{
				State: newStateWithSchema(getServerGroupTestSchema()),
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

func TestServerGroupResource_NilClientWarning(t *testing.T) {
	ctx := context.Background()
	s := getServerGroupTestSchema()
	r := &ServerGroupResource{}

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

func TestServerGroupResource_ImportState(t *testing.T) {
	ctx := context.Background()
	r := &ServerGroupResource{}
	s := getServerGroupTestSchema()

	t.Run("passthrough import by id", func(t *testing.T) {
		req := resource.ImportStateRequest{ID: "prod.example.org/prod-servers"}
		resp := &resource.ImportStateResponse{
			State: newStateWithSchema(s),
		}
		r.ImportState(ctx, req, resp)
		require.False(t, resp.Diagnostics.HasError())

		var result ServerGroupResourceModel
		resp.State.Get(ctx, &result)
		assert.Equal(t, "prod.example.org/prod-servers", result.ID.ValueString())
		assert.Equal(t, "prod.example.org", result.TrustDomainName.ValueString())
		assert.Equal(t, "prod-servers", result.Name.ValueString())
	})
}

func buildServerGroupConfigFromModel(data ServerGroupResourceModel) tfsdk.Config {
	plan := newPlanWithSchema(getServerGroupTestSchema())
	ctx := context.Background()
	plan.Set(ctx, &data)

	return tfsdk.Config{
		Raw:    plan.Raw,
		Schema: getServerGroupTestSchema(),
	}
}

func getServerGroupTestSchema() schema.Schema {
	r := &ServerGroupResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}

// --- Schema plan modifier tests ---

func TestServerGroupResource_Schema_RequiresReplace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &ServerGroupResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	tests := []struct {
		attrPath      string
		shouldReplace bool
	}{
		{"name", true},
		{"trust_domain_name", true},
		{"id", false},
		{"description", false},
		{"node_attestation", false},
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

func TestServerGroupResource_CreateAndDelete(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	cert := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"

	mockClient.EXPECT().
		PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything, mock.Anything).
		Return(&swaclient.PostServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.ServerGroupResponse{
				Name:            "test-sg",
				TrustDomainName: "test-td",
				NodeAttestation: &struct {
					K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
					X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
				}{
					X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: cert},
				},
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name:            "test-sg",
				TrustDomainName: "test-td",
				NodeAttestation: &struct {
					K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
					X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
				}{
					X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: cert},
				},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"
  node_attestation = {
    x509pop = {
      ca_certificates = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    }
  }
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "name", "test-sg"),
					tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "id", "test-td/test-sg"),
					tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "trust_domain_name", "test-td"),
				),
			},
		},
	})
}

func TestServerGroupResource_NameChange_RequiresReplace(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	cert := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
	nodeAtt := &struct {
		K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
		X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
	}{
		X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: cert},
	}

	mockClient.EXPECT().
		PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything,
			mock.MatchedBy(func(body swaclient.PostServerGroupJSONRequestBody) bool { return body.Name == "sg-one" })).
		Return(&swaclient.PostServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.ServerGroupResponse{
				Name: "sg-one", TrustDomainName: "test-td", NodeAttestation: nodeAtt,
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything,
			mock.MatchedBy(func(body swaclient.PostServerGroupJSONRequestBody) bool { return body.Name == "sg-two" })).
		Return(&swaclient.PostServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.ServerGroupResponse{
				Name: "sg-two", TrustDomainName: "test-td", NodeAttestation: nodeAtt,
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "sg-one", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "sg-one", TrustDomainName: "test-td", NodeAttestation: nodeAtt,
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "sg-two", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "sg-two", TrustDomainName: "test-td", NodeAttestation: nodeAtt,
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteServerGroupWithResponse(mock.Anything, "test-td", "sg-one", mock.Anything).
		Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	mockClient.EXPECT().
		DeleteServerGroupWithResponse(mock.Anything, "test-td", "sg-two", mock.Anything).
		Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "sg-one"
  trust_domain_name = "test-td"
  node_attestation = {
    x509pop = {
      ca_certificates = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    }
  }
}
`,
				Check: tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "name", "sg-one"),
			},
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "sg-two"
  trust_domain_name = "test-td"
  node_attestation = {
    x509pop = {
      ca_certificates = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    }
  }
}
`,
				Check: tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "name", "sg-two"),
			},
		},
	})
}

func TestServerGroupResource_RemoveX509PopKeepK8sPsat(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	saList := []string{"ns:sa"}
	audience := []string{"swa-server"}
	cert := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"

	bothNodeAtt := &struct {
		K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
		X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
	}{
		X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: cert},
		K8sPsat: &swaclient.K8sPsatConfigurationInput{
			Clusters: &map[string]swaclient.K8sPsatCluster{
				"cluster-1": {ServiceAccountAllowList: &saList, Audience: &audience},
			},
		},
	}
	k8sOnlyNodeAtt := &struct {
		K8sPsat *swaclient.K8sPsatConfigurationInput `json:"k8s_psat,omitempty"`
		X509pop *swaclient.X509PopConfigurationInput `json:"x509pop,omitempty"`
	}{
		K8sPsat: &swaclient.K8sPsatConfigurationInput{
			Clusters: &map[string]swaclient.K8sPsatCluster{
				"cluster-1": {ServiceAccountAllowList: &saList, Audience: &audience},
			},
		},
	}

	mockClient.EXPECT().
		PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything, mock.Anything).
		Return(&swaclient.PostServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", NodeAttestation: bothNodeAtt,
			},
		}, nil).Times(1)

	// Two reads: post-apply step-1 refresh + pre-plan step-2 refresh.
	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", NodeAttestation: bothNodeAtt,
			},
		}, nil).Times(2)

	mockClient.EXPECT().
		PatchServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything,
			mock.MatchedBy(func(body swaclient.PatchServerGroupJSONRequestBody) bool {
				return body.NodeAttestation != nil &&
					body.NodeAttestation.X509pop == nil &&
					body.NodeAttestation.K8sPsat != nil
			})).
		Return(&swaclient.PatchServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", NodeAttestation: k8sOnlyNodeAtt,
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", NodeAttestation: k8sOnlyNodeAtt,
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"
  node_attestation = {
    x509pop = {
      ca_certificates = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    }
    k8s_psat = {
      clusters = {
        "cluster-1" = {
          service_account_allow_list = ["ns:sa"]
          audience                   = ["swa-server"]
        }
      }
    }
  }
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttrSet("conjur_swa_server_group.test", "node_attestation.x509pop.ca_certificates"),
					tfresource.TestCheckResourceAttrSet("conjur_swa_server_group.test", "node_attestation.k8s_psat.clusters.cluster-1.service_account_allow_list.0"),
				),
			},
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"
  node_attestation = {
    k8s_psat = {
      clusters = {
        "cluster-1" = {
          service_account_allow_list = ["ns:sa"]
          audience                   = ["swa-server"]
        }
      }
    }
  }
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckNoResourceAttr("conjur_swa_server_group.test", "node_attestation.x509pop.ca_certificates"),
					tfresource.TestCheckResourceAttrSet("conjur_swa_server_group.test", "node_attestation.k8s_psat.clusters.cluster-1.service_account_allow_list.0"),
				),
			},
		},
	})
}
