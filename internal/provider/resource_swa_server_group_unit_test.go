package provider

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"testing"
	"time"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
	swamocks "github.com/cyberark/terraform-provider-conjur/internal/swa/client/mocks"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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

func mustStringList(t *testing.T, values ...string) types.List {
	t.Helper()
	list, diags := types.ListValueFrom(context.Background(), types.StringType, values)
	require.False(t, diags.HasError(), "failed to build test list: %v", diags)
	return list
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

// TestUpdateAttestationFromResponse verifies that updateAttestationFromResponse fully
// reconciles state from the API response (rather than merging into whatever was already in the
// model), so attestation methods or clusters removed server-side actually disappear from state
// on the next Read instead of persisting indefinitely.
func TestUpdateAttestationFromResponse(t *testing.T) {
	ctx := context.Background()

	t.Run("nil response clears node attestation", func(t *testing.T) {
		model := &ServerGroupResourceModel{
			Attestation: &AttestationModel{
				X509Pop: &X509PopModel{CaCertificates: types.StringValue("stale-cert")},
			},
		}
		diags := updateAttestationFromResponse(ctx, model, nil)
		assert.False(t, diags.HasError())
		assert.Nil(t, model.Attestation)
	})

	t.Run("x509pop removed server-side is removed from state", func(t *testing.T) {
		model := &ServerGroupResourceModel{
			Attestation: &AttestationModel{
				X509Pop: &X509PopModel{CaCertificates: types.StringValue("stale-cert")},
			},
		}
		at := &swaclient.AttestationConfiguration{
			K8sPsat: &swaclient.K8sPsatConfigurationInput{
				Clusters: &map[string]swaclient.K8sPsatCluster{
					"cluster-a": {},
				},
			},
		}

		diags := updateAttestationFromResponse(ctx, model, at)
		assert.False(t, diags.HasError())
		require.NotNil(t, model.Attestation)
		assert.Nil(t, model.Attestation.X509Pop, "x509pop should be cleared once the server no longer reports it")
		require.NotNil(t, model.Attestation.K8sPsat)
		assert.Contains(t, model.Attestation.K8sPsat.Clusters.Elements(), "cluster-a")
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
			Attestation: &AttestationModel{
				K8sPsat: &K8sPsatModel{
					Clusters: mustClustersMap(t, ctx, map[string]K8sPsatClusterModel{
						"cluster-a": clusterA,
						"cluster-b": clusterB,
					}),
				},
			},
		}
		at := &swaclient.AttestationConfiguration{
			K8sPsat: &swaclient.K8sPsatConfigurationInput{
				Clusters: &map[string]swaclient.K8sPsatCluster{
					"cluster-a": {},
				},
			},
		}

		diags := updateAttestationFromResponse(ctx, model, at)
		assert.False(t, diags.HasError())
		require.NotNil(t, model.Attestation.K8sPsat)
		assert.Contains(t, model.Attestation.K8sPsat.Clusters.Elements(), "cluster-a")
		assert.NotContains(t, model.Attestation.K8sPsat.Clusters.Elements(), "cluster-b", "cluster-b was removed server-side and must not persist in state")
	})

	t.Run("k8s_psat removed server-side is removed from state", func(t *testing.T) {
		emptyCluster := K8sPsatClusterModel{
			ServiceAccountAllowList: types.ListNull(types.StringType),
			Audience:                types.ListNull(types.StringType),
			AllowedPodLabelKeys:     types.ListNull(types.StringType),
			AllowedNodeLabelKeys:    types.ListNull(types.StringType),
		}
		model := &ServerGroupResourceModel{
			Attestation: &AttestationModel{
				X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				K8sPsat: &K8sPsatModel{
					Clusters: mustClustersMap(t, ctx, map[string]K8sPsatClusterModel{
						"cluster-a": emptyCluster,
					}),
				},
			},
		}
		at := &swaclient.AttestationConfiguration{
			X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "cert"},
		}

		diags := updateAttestationFromResponse(ctx, model, at)
		assert.False(t, diags.HasError())
		require.NotNil(t, model.Attestation)
		assert.Nil(t, model.Attestation.K8sPsat, "k8s_psat should be cleared once the server no longer reports it")
	})

	t.Run("gcp_service_account from attestation field is reconciled into state", func(t *testing.T) {
		model := &ServerGroupResourceModel{}
		audiences := []string{"urn:panw:swa"}
		at := &swaclient.AttestationConfiguration{
			GcpServiceAccount: &swaclient.GcpServiceAccountAttestationConfiguration{
				AllowedProjectIds: []string{"project-a", "project-b"},
				Audiences:         &audiences,
			},
		}

		diags := updateAttestationFromResponse(ctx, model, at)
		assert.False(t, diags.HasError())
		require.NotNil(t, model.Attestation)
		require.NotNil(t, model.Attestation.GcpServiceAccount)
		assert.Nil(t, model.Attestation.X509Pop)
		assert.Nil(t, model.Attestation.K8sPsat)

		var projects []string
		require.False(t, model.Attestation.GcpServiceAccount.AllowedProjectIDs.ElementsAs(ctx, &projects, false).HasError())
		assert.Equal(t, []string{"project-a", "project-b"}, projects)

		var auds []string
		require.False(t, model.Attestation.GcpServiceAccount.Audiences.ElementsAs(ctx, &auds, false).HasError())
		assert.Equal(t, []string{"urn:panw:swa"}, auds)
	})

	t.Run("aws_iid from attestation field is reconciled into state", func(t *testing.T) {
		model := &ServerGroupResourceModel{}
		partition := swaclient.Aws
		at := &swaclient.AttestationConfiguration{
			AwsIid: &swaclient.AwsIidAttestationConfiguration{
				AssumeRole: new("SWAServerRole"),
				Partition:  &partition,
				VerifyOrganization: &swaclient.AwsIidVerifyOrganizationConfiguration{
					ManagementAccountId:     new("123456789012"),
					ManagementAccountRegion: new("us-east-1"),
					AssumeOrgRole:           new("AWSOrganizationsReadOnlyAccess"),
					OrgAccountMapTtl:        new("15m"),
				},
			},
		}

		diags := updateAttestationFromResponse(ctx, model, at)
		assert.False(t, diags.HasError())
		require.NotNil(t, model.Attestation)
		require.NotNil(t, model.Attestation.AwsIid)
		assert.Equal(t, "SWAServerRole", model.Attestation.AwsIid.AssumeRole.ValueString())
		assert.Equal(t, "aws", model.Attestation.AwsIid.Partition.ValueString())

		require.NotNil(t, model.Attestation.AwsIid.VerifyOrganization)
		vo := model.Attestation.AwsIid.VerifyOrganization
		assert.Equal(t, "123456789012", vo.ManagementAccountID.ValueString())
		assert.Equal(t, "us-east-1", vo.ManagementAccountRegion.ValueString())
		assert.Equal(t, "AWSOrganizationsReadOnlyAccess", vo.AssumeOrgRole.ValueString())
		assert.Equal(t, "15m", vo.OrgAccountMapTTL.ValueString())
		assert.True(t, vo.AccountListFile.IsNull())
	})
}

func TestBuildK8sPsatClusters(t *testing.T) {
	ctx := context.Background()

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
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name: "prod-servers",
					Attestation: &swaclient.AttestationConfiguration{
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
				Attestation: &AttestationModel{
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
					Attestation: &swaclient.AttestationConfiguration{
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
			// When gcp_service_account is configured, the request must go out on the newer
			// attestation API field.
			name: "successful creation with GCP service account attestation",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: &AttestationModel{
					GcpServiceAccount: &GcpServiceAccountModel{
						AllowedProjectIDs: mustStringList(t, "project-a", "project-b"),
						Audiences:         mustStringList(t, "urn:panw:swa"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				audiences := []string{"urn:panw:swa"}
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name: "prod-servers",
					Attestation: &swaclient.AttestationConfiguration{
						GcpServiceAccount: &swaclient.GcpServiceAccountAttestationConfiguration{
							AllowedProjectIds: []string{"project-a", "project-b"},
							Audiences:         &audiences,
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
			// When aws_iid is configured, the request must go out on the attestation API
			// field, including the nested verify_organization block.
			name: "successful creation with AWS IID attestation",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: &AttestationModel{
					AwsIid: &AwsIidModel{
						AssumeRole: types.StringValue("SWAServerRole"),
						Partition:  types.StringValue("aws"),
						VerifyOrganization: &AwsIidVerifyOrgModel{
							ManagementAccountID: types.StringValue("123456789012"),
							AssumeOrgRole:       types.StringValue("AWSOrganizationsReadOnlyAccess"),
						},
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				partition := swaclient.Aws
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name: "prod-servers",
					Attestation: &swaclient.AttestationConfiguration{
						AwsIid: &swaclient.AwsIidAttestationConfiguration{
							AssumeRole: new("SWAServerRole"),
							Partition:  &partition,
							VerifyOrganization: &swaclient.AwsIidVerifyOrganizationConfiguration{
								ManagementAccountId: new("123456789012"),
								AssumeOrgRole:       new("AWSOrganizationsReadOnlyAccess"),
							},
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
			// The spec allows a server group with no attestation at all; the request omits
			// the attestation field entirely.
			name: "successful creation without attestation block",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name: "prod-servers",
				}).Return(&swaclient.PostServerGroupResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: sg,
				}, nil)
			},
			expectedError: false,
		},
		{
			// An attestation block with no methods is also valid; it serializes to an empty
			// attestation object.
			name: "successful creation with empty attestation block",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Attestation:     &AttestationModel{},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name:        "prod-servers",
					Attestation: &swaclient.AttestationConfiguration{},
				}).Return(&swaclient.PostServerGroupResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: sg,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during creation",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("cert"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name: "prod-servers",
					Attestation: &swaclient.AttestationConfiguration{
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
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("cert"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name: "prod-servers",
					Attestation: &swaclient.AttestationConfiguration{
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
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{
						CaCertificates: types.StringValue("stale-cert"),
					},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				sg.Attestation = &swaclient.AttestationConfiguration{
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
				Attestation: &AttestationModel{
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
				Attestation: &AttestationModel{
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
				Attestation: &AttestationModel{
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
		{
			name: "nil response body on 200",
			data: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.GetServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetServerGroupResponse{
						HTTPResponse: makeHTTPResponse(http.StatusOK),
					}, nil)
			},
			expectedError: true,
			errorContains: "No response body",
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
					require.NotNil(t, result.Attestation)
					require.NotNil(t, result.Attestation.X509Pop)
					assert.Equal(t, tt.expectedCert, result.Attestation.X509Pop.CaCertificates.ValueString())
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
				Attestation: &AttestationModel{
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
				Attestation: &AttestationModel{
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
				Attestation: &AttestationModel{
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
				Attestation: &AttestationModel{
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
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				desc := "updated description"
				sg.Description = &desc
				m.On("PatchServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PatchServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchServerGroupJSONRequestBody{
					Description: &desc,
					Attestation: &swaclient.AttestationConfiguration{
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
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PatchServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchServerGroupJSONRequestBody{
					Attestation: &swaclient.AttestationConfiguration{
						X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "cert"},
					},
				}).Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error updating server group",
		},
		{
			// Removing the attestation block is a valid update; the request omits the
			// attestation field entirely.
			name: "successful update removing attestation",
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
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				sg.Attestation = nil
				m.On("PatchServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PatchServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchServerGroupJSONRequestBody{}).Return(&swaclient.PatchServerGroupResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: sg,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "non-200 status code",
			plan: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PatchServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchServerGroupJSONRequestBody{
					Attestation: &swaclient.AttestationConfiguration{
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
		{
			name: "nil response body on 200",
			plan: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: &AttestationModel{
					X509Pop: &X509PopModel{CaCertificates: types.StringValue("cert")},
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchServerGroupWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PatchServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchServerGroupJSONRequestBody{
					Attestation: &swaclient.AttestationConfiguration{
						X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "cert"},
					},
				}).Return(&swaclient.PatchServerGroupResponse{
					HTTPResponse: makeHTTPResponse(http.StatusOK),
				}, nil)
			},
			expectedError: true,
			errorContains: "No response body",
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
		{"attestation", false},
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
				Attestation: &swaclient.AttestationConfiguration{
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
				Attestation: &swaclient.AttestationConfiguration{
					X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: cert},
				},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"
  attestation = {
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
	att := &swaclient.AttestationConfiguration{
		X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: cert},
	}

	mockClient.EXPECT().
		PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything,
			mock.MatchedBy(func(body swaclient.PostServerGroupJSONRequestBody) bool { return body.Name == "sg-one" })).
		Return(&swaclient.PostServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.ServerGroupResponse{
				Name: "sg-one", TrustDomainName: "test-td", Attestation: att,
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything,
			mock.MatchedBy(func(body swaclient.PostServerGroupJSONRequestBody) bool { return body.Name == "sg-two" })).
		Return(&swaclient.PostServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.ServerGroupResponse{
				Name: "sg-two", TrustDomainName: "test-td", Attestation: att,
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "sg-one", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "sg-one", TrustDomainName: "test-td", Attestation: att,
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "sg-two", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "sg-two", TrustDomainName: "test-td", Attestation: att,
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteServerGroupWithResponse(mock.Anything, "test-td", "sg-one", mock.Anything).
		Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	mockClient.EXPECT().
		DeleteServerGroupWithResponse(mock.Anything, "test-td", "sg-two", mock.Anything).
		Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "sg-one"
  trust_domain_name = "test-td"
  attestation = {
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
  attestation = {
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

	bothAtt := &swaclient.AttestationConfiguration{
		X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: cert},
		K8sPsat: &swaclient.K8sPsatConfigurationInput{
			Clusters: &map[string]swaclient.K8sPsatCluster{
				"cluster-1": {ServiceAccountAllowList: &saList, Audience: &audience},
			},
		},
	}
	k8sOnlyAtt := &swaclient.AttestationConfiguration{
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
				Name: "test-sg", TrustDomainName: "test-td", Attestation: bothAtt,
			},
		}, nil).Times(1)

	// Two reads: post-apply step-1 refresh + pre-plan step-2 refresh.
	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", Attestation: bothAtt,
			},
		}, nil).Times(2)

	mockClient.EXPECT().
		PatchServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything,
			mock.MatchedBy(func(body swaclient.PatchServerGroupJSONRequestBody) bool {
				return body.Attestation != nil &&
					body.Attestation.X509pop == nil &&
					body.Attestation.K8sPsat != nil
			})).
		Return(&swaclient.PatchServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", Attestation: k8sOnlyAtt,
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", Attestation: k8sOnlyAtt,
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"
  attestation = {
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
					tfresource.TestCheckResourceAttrSet("conjur_swa_server_group.test", "attestation.x509pop.ca_certificates"),
					tfresource.TestCheckResourceAttrSet("conjur_swa_server_group.test", "attestation.k8s_psat.clusters.cluster-1.service_account_allow_list.0"),
				),
			},
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"
  attestation = {
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
					tfresource.TestCheckNoResourceAttr("conjur_swa_server_group.test", "attestation.x509pop.ca_certificates"),
					tfresource.TestCheckResourceAttrSet("conjur_swa_server_group.test", "attestation.k8s_psat.clusters.cluster-1.service_account_allow_list.0"),
				),
			},
		},
	})
}

// Regression test: creating a gcp_service_account server group without an explicit
// `audiences` list used to fail with "Provider produced inconsistent result after
// apply", because the API applies a server-side default (`urn:panw:swa`) that the
// `audiences` attribute's schema didn't mark Computed. Terraform core saw the config's
// null value as final at plan time, then rejected the non-null value the mocked Create
// response returns, exactly reproducing the failure this test guards against.
func TestServerGroupResource_GcpServiceAccount_DefaultAudienceOmitted(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	defaultAudiences := []string{"urn:panw:swa"}
	att := &swaclient.AttestationConfiguration{
		GcpServiceAccount: &swaclient.GcpServiceAccountAttestationConfiguration{
			AllowedProjectIds: []string{"project-a"},
			Audiences:         &defaultAudiences,
		},
	}

	mockClient.EXPECT().
		PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything, mock.Anything).
		Return(&swaclient.PostServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", Attestation: att,
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", Attestation: att,
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"
  attestation = {
    gcp_service_account = {
      allowed_project_ids = ["project-a"]
    }
  }
}
`,
				Check: tfresource.TestCheckResourceAttr(
					"conjur_swa_server_group.test", "attestation.gcp_service_account.audiences.0", "urn:panw:swa",
				),
			},
		},
	})
}

func TestServerGroupResource_ValidateConfig_RejectsEmptyGCPAllowedProjectIDs(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"

  attestation = {
    gcp_service_account = {
      allowed_project_ids = []
    }
  }
}
`,
				ExpectError: regexp.MustCompile(`(?s)allowed_project_ids.*at least 1`),
			},
		},
	})
}

// TestServerGroupResource_ValidateConfig_RejectsNodeAttestation exercises the
// deprecated node_attestation attribute: configs written against the old,
// never-released attribute name must still parse (so the schema keeps the
// attribute defined) but ValidateConfig must reject them with a clear message
// pointing users to the renamed `attestation` attribute.
func TestServerGroupResource_ValidateConfig_RejectsNodeAttestation(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"

  node_attestation = {
    x509pop = {
      ca_certificates = "dummy"
    }
  }
}
`,
				ExpectError: regexp.MustCompile(`(?s)node_attestation.*.?attestation`),
			},
		},
	})
}

// --- aws_iid attestation: HCL combination coverage ---

// awsIidTestConfig wraps an `aws_iid = { ... }` body (the attrs, one per line) in a
// full server group resource so each combination case only has to spell out the
// fields relevant to it.
func awsIidTestConfig(name, trustDomain, awsIidBody string) string {
	return fmt.Sprintf(`
resource "conjur_swa_server_group" "test" {
  name              = %q
  trust_domain_name = %q
  attestation = {
    aws_iid = {
%s
    }
  }
}
`, name, trustDomain, awsIidBody)
}

// TestServerGroupResource_AwsIid_HCLCombinations drives the aws_iid attestation
// block through Terraform's plan/apply lifecycle (via the mocked SWA client) for
// every meaningful combination of its fields: assume_role alone, each partition
// value, verify_organization via its IAM-role fields, verify_organization via its
// account_list_file fields, an empty aws_iid block (default partition only), an
// empty verify_organization block, and every field set at once. This exercises the
// same request-building/state-reconciliation path a real apply would take, without
// needing a live Conjur backend.
func TestServerGroupResource_AwsIid_HCLCombinations(t *testing.T) {
	t.Parallel()

	assumeRole := "service-role/SWAServerRole"

	tests := []struct {
		name   string
		hcl    string
		want   *swaclient.AwsIidAttestationConfiguration
		checks []tfresource.TestCheckFunc
	}{
		{
			name: "assume_role only (partition defaults to aws)",
			hcl:  fmt.Sprintf(`assume_role = %q`, assumeRole),
			want: &swaclient.AwsIidAttestationConfiguration{
				AssumeRole: new(assumeRole),
				Partition:  new(swaclient.Aws),
			},
			checks: []tfresource.TestCheckFunc{
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.assume_role", assumeRole),
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.partition", "aws"),
			},
		},
		{
			name: "explicit partition aws",
			hcl:  `partition = "aws"`,
			want: &swaclient.AwsIidAttestationConfiguration{Partition: new(swaclient.Aws)},
			checks: []tfresource.TestCheckFunc{
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.partition", "aws"),
				tfresource.TestCheckNoResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.assume_role"),
			},
		},
		{
			name: "explicit partition aws-cn",
			hcl:  `partition = "aws-cn"`,
			want: &swaclient.AwsIidAttestationConfiguration{Partition: new(swaclient.AwsCn)},
			checks: []tfresource.TestCheckFunc{
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.partition", "aws-cn"),
			},
		},
		{
			name: "explicit partition aws-us-gov",
			hcl:  `partition = "aws-us-gov"`,
			want: &swaclient.AwsIidAttestationConfiguration{Partition: new(swaclient.AwsUsGov)},
			checks: []tfresource.TestCheckFunc{
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.partition", "aws-us-gov"),
			},
		},
		{
			name: "empty aws_iid block still gets default partition",
			hcl:  ``,
			want: &swaclient.AwsIidAttestationConfiguration{Partition: new(swaclient.Aws)},
			checks: []tfresource.TestCheckFunc{
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.partition", "aws"),
				tfresource.TestCheckNoResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.assume_role"),
			},
		},
		{
			name: "verify_organization via IAM role fields",
			hcl: `
      verify_organization = {
        management_account_id     = "123456789012"
        management_account_region = "us-east-1"
        assume_org_role            = "AWSOrganizationsReadOnlyAccess"
        org_account_map_ttl        = "15m"
      }`,
			want: &swaclient.AwsIidAttestationConfiguration{
				Partition: new(swaclient.Aws),
				VerifyOrganization: &swaclient.AwsIidVerifyOrganizationConfiguration{
					ManagementAccountId:     new("123456789012"),
					ManagementAccountRegion: new("us-east-1"),
					AssumeOrgRole:           new("AWSOrganizationsReadOnlyAccess"),
					OrgAccountMapTtl:        new("15m"),
				},
			},
			checks: []tfresource.TestCheckFunc{
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.management_account_id", "123456789012"),
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.management_account_region", "us-east-1"),
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.assume_org_role", "AWSOrganizationsReadOnlyAccess"),
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.org_account_map_ttl", "15m"),
				tfresource.TestCheckNoResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.account_list_file"),
			},
		},
		{
			name: "verify_organization via account_list_file",
			hcl: `
      verify_organization = {
        account_list_file = "/etc/spire/org-accounts.json"
      }`,
			want: &swaclient.AwsIidAttestationConfiguration{
				Partition: new(swaclient.Aws),
				VerifyOrganization: &swaclient.AwsIidVerifyOrganizationConfiguration{
					AccountListFile: new("/etc/spire/org-accounts.json"),
				},
			},
			checks: []tfresource.TestCheckFunc{
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.account_list_file", "/etc/spire/org-accounts.json"),
				tfresource.TestCheckNoResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.management_account_id"),
			},
		},
		{
			name: "empty verify_organization block",
			hcl: `
      verify_organization = {}`,
			want: &swaclient.AwsIidAttestationConfiguration{
				Partition:          new(swaclient.Aws),
				VerifyOrganization: &swaclient.AwsIidVerifyOrganizationConfiguration{},
			},
			checks: []tfresource.TestCheckFunc{
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.%", "5"),
			},
		},
		{
			name: "every field set at once",
			hcl: fmt.Sprintf(`
      assume_role = %q
      partition   = "aws-cn"
      verify_organization = {
        management_account_id     = "123456789012"
        management_account_region = "us-east-1"
        assume_org_role            = "AWSOrganizationsReadOnlyAccess"
        org_account_map_ttl        = "15m"
        account_list_file          = "/etc/spire/org-accounts.json"
      }`, assumeRole),
			want: &swaclient.AwsIidAttestationConfiguration{
				AssumeRole: new(assumeRole),
				Partition:  new(swaclient.AwsCn),
				VerifyOrganization: &swaclient.AwsIidVerifyOrganizationConfiguration{
					ManagementAccountId:     new("123456789012"),
					ManagementAccountRegion: new("us-east-1"),
					AssumeOrgRole:           new("AWSOrganizationsReadOnlyAccess"),
					OrgAccountMapTtl:        new("15m"),
					AccountListFile:         new("/etc/spire/org-accounts.json"),
				},
			},
			checks: []tfresource.TestCheckFunc{
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.assume_role", assumeRole),
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.partition", "aws-cn"),
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.management_account_id", "123456789012"),
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.management_account_region", "us-east-1"),
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.assume_org_role", "AWSOrganizationsReadOnlyAccess"),
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.org_account_map_ttl", "15m"),
				tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.verify_organization.account_list_file", "/etc/spire/org-accounts.json"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockClient := swamocks.NewMockClientWithResponsesInterface(t)

			att := &swaclient.AttestationConfiguration{AwsIid: tc.want}

			mockClient.EXPECT().
				PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything,
					mock.MatchedBy(func(body swaclient.PostServerGroupJSONRequestBody) bool {
						return body.Attestation != nil && reflect.DeepEqual(body.Attestation.AwsIid, tc.want)
					})).
				Return(&swaclient.PostServerGroupResponse{
					HTTPResponse: makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: &swaclient.ServerGroupResponse{
						Name: "test-sg", TrustDomainName: "test-td", Attestation: att,
					},
				}, nil).Times(1)

			mockClient.EXPECT().
				GetServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
				Return(&swaclient.GetServerGroupResponse{
					HTTPResponse: makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
						Name: "test-sg", TrustDomainName: "test-td", Attestation: att,
					},
				}, nil).Maybe()

			mockClient.EXPECT().
				DeleteServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
				Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

			tfresource.Test(t, tfresource.TestCase{
				ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
				Steps: []tfresource.TestStep{
					{
						Config: awsIidTestConfig("test-sg", "test-td", tc.hcl),
						Check:  tfresource.ComposeTestCheckFunc(tc.checks...),
					},
				},
			})
		})
	}
}

// TestServerGroupResource_AwsIid_ValidateConfig_RejectsInvalidPartition exercises the
// partition attribute's OneOf validator: only aws/aws-cn/aws-us-gov are accepted.
func TestServerGroupResource_AwsIid_ValidateConfig_RejectsInvalidPartition(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config:      awsIidTestConfig("test-sg", "test-td", `partition = "invalid-partition"`),
				ExpectError: regexp.MustCompile(`(?s)value must be one of`),
			},
		},
	})
}

// TestServerGroupResource_AwsIid_ReplacesX509Pop exercises switching a server group's
// attestation method from x509pop to aws_iid: the request must clear x509pop and set
// aws_iid on the same PATCH, and the old x509pop values must not persist in state.
func TestServerGroupResource_AwsIid_ReplacesX509Pop(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	cert := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
	assumeRole := "service-role/SWAServerRole"

	x509Att := &swaclient.AttestationConfiguration{
		X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: cert},
	}
	awsIidAtt := &swaclient.AttestationConfiguration{
		AwsIid: &swaclient.AwsIidAttestationConfiguration{
			AssumeRole: new(assumeRole),
			Partition:  new(swaclient.Aws),
		},
	}

	mockClient.EXPECT().
		PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything, mock.Anything).
		Return(&swaclient.PostServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", Attestation: x509Att,
			},
		}, nil).Times(1)

	// Two reads: post-apply step-1 refresh + pre-plan step-2 refresh.
	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", Attestation: x509Att,
			},
		}, nil).Times(2)

	mockClient.EXPECT().
		PatchServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything,
			mock.MatchedBy(func(body swaclient.PatchServerGroupJSONRequestBody) bool {
				return body.Attestation != nil &&
					body.Attestation.X509pop == nil &&
					body.Attestation.AwsIid != nil
			})).
		Return(&swaclient.PatchServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", Attestation: awsIidAtt,
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.GetServerGroupResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerGroupResponse{
				Name: "test-sg", TrustDomainName: "test-td", Attestation: awsIidAtt,
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteServerGroupWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything).
		Return(&swaclient.DeleteServerGroupResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"
  attestation = {
    x509pop = {
      ca_certificates = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    }
  }
}
`,
				Check: tfresource.TestCheckResourceAttrSet("conjur_swa_server_group.test", "attestation.x509pop.ca_certificates"),
			},
			{
				Config: awsIidTestConfig("test-sg", "test-td", fmt.Sprintf(`assume_role = %q`, assumeRole)),
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckNoResourceAttr("conjur_swa_server_group.test", "attestation.x509pop.ca_certificates"),
					tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.assume_role", assumeRole),
					tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.aws_iid.partition", "aws"),
				),
			},
		},
	})
}
