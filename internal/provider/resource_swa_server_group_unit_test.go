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
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
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

// The mk* helpers build the types.Object values that AttestationModel and its variant fields now
// hold, from the plain struct fixtures used throughout these tests. Each defaults an unset nested
// object field to a typed null so ObjectValueFrom succeeds.
func mkObjectFromValue[M any](attrTypes map[string]attr.Type, m M) types.Object {
	obj, diags := types.ObjectValueFrom(context.Background(), attrTypes, m)
	if diags.HasError() {
		panic(fmt.Sprintf("mkObjectFromValue[%T]: %v", m, diags))
	}
	return obj
}

func mkX509Pop(m X509PopModel) types.Object { return mkObjectFromValue(x509PopAttrTypes(), m) }
func mkK8sPsat(m K8sPsatModel) types.Object { return mkObjectFromValue(k8sPsatAttrTypes(), m) }
func mkGcpServiceAccount(m GcpServiceAccountModel) types.Object {
	return mkObjectFromValue(gcpServiceAccountAttrTypes(), m)
}
func mkGeminiEnterprise(m GeminiEnterpriseModel) types.Object {
	return mkObjectFromValue(geminiEnterpriseAttrTypes(), m)
}
func mkK8sJwt(m K8sJwtModel) types.Object { return mkObjectFromValue(k8sJwtAttrTypes(), m) }
func mkAwsIidVerifyOrg(m AwsIidVerifyOrgModel) types.Object {
	return mkObjectFromValue(awsIidVerifyOrgAttrTypes(), m)
}

func mkAwsIid(m AwsIidModel) types.Object {
	if len(m.VerifyOrganization.AttributeTypes(context.Background())) == 0 {
		m.VerifyOrganization = types.ObjectNull(awsIidVerifyOrgAttrTypes())
	}
	return mkObjectFromValue(awsIidAttrTypes(), m)
}

func mkAttestation(m AttestationModel) types.Object {
	ctx := context.Background()
	if len(m.X509Pop.AttributeTypes(ctx)) == 0 {
		m.X509Pop = types.ObjectNull(x509PopAttrTypes())
	}
	if len(m.K8sPsat.AttributeTypes(ctx)) == 0 {
		m.K8sPsat = types.ObjectNull(k8sPsatAttrTypes())
	}
	if len(m.GcpServiceAccount.AttributeTypes(ctx)) == 0 {
		m.GcpServiceAccount = types.ObjectNull(gcpServiceAccountAttrTypes())
	}
	if len(m.GeminiEnterprise.AttributeTypes(ctx)) == 0 {
		m.GeminiEnterprise = types.ObjectNull(geminiEnterpriseAttrTypes())
	}
	if len(m.AwsIid.AttributeTypes(ctx)) == 0 {
		m.AwsIid = types.ObjectNull(awsIidAttrTypes())
	}
	if len(m.K8sJwt.AttributeTypes(ctx)) == 0 {
		m.K8sJwt = types.ObjectNull(k8sJwtAttrTypes())
	}
	return mkObjectFromValue(attestationAttrTypes(), m)
}

// normalizeServerGroupModel fills typed nulls for the top-level object fields that fixtures leave
// as zero-value types.Object values, matching what the framework produces when it reads a real
// plan/state. Without it, Set rejects the model because an untyped object can't be reconciled
// against the schema's typed attestation object.
func normalizeServerGroupModel(m *ServerGroupResourceModel) {
	ctx := context.Background()
	if len(m.Attestation.AttributeTypes(ctx)) == 0 {
		m.Attestation = types.ObjectNull(attestationAttrTypes())
	}
	if len(m.NodeAttestation.AttributeTypes(ctx)) == 0 {
		m.NodeAttestation = types.ObjectNull(attestationAttrTypes())
	}
}

// The decode* helpers reverse the mk* helpers for assertions on reconciled state.
func decodeObject[M any](t *testing.T, obj types.Object) M {
	t.Helper()
	var m M
	var diags diag.Diagnostics
	diags.Append(obj.As(context.Background(), &m, basetypes.ObjectAsOptions{})...)
	require.False(t, diags.HasError())
	return m
}

func decodeAttestation(t *testing.T, obj types.Object) AttestationModel {
	return decodeObject[AttestationModel](t, obj)
}
func decodeK8sPsat(t *testing.T, obj types.Object) K8sPsatModel {
	return decodeObject[K8sPsatModel](t, obj)
}
func decodeGcpServiceAccount(t *testing.T, obj types.Object) GcpServiceAccountModel {
	return decodeObject[GcpServiceAccountModel](t, obj)
}
func decodeGeminiEnterprise(t *testing.T, obj types.Object) GeminiEnterpriseModel {
	return decodeObject[GeminiEnterpriseModel](t, obj)
}
func decodeAwsIid(t *testing.T, obj types.Object) AwsIidModel {
	return decodeObject[AwsIidModel](t, obj)
}
func decodeAwsIidVerifyOrg(t *testing.T, obj types.Object) AwsIidVerifyOrgModel {
	return decodeObject[AwsIidVerifyOrgModel](t, obj)
}
func decodeK8sJwt(t *testing.T, obj types.Object) K8sJwtModel {
	return decodeObject[K8sJwtModel](t, obj)
}
func decodeX509Pop(t *testing.T, obj types.Object) X509PopModel {
	return decodeObject[X509PopModel](t, obj)
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
			Attestation: mkAttestation(AttestationModel{
				X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("stale-cert")}),
			}),
		}
		diags := updateAttestationFromResponse(ctx, model, nil)
		assert.False(t, diags.HasError())
		assert.True(t, model.Attestation.IsNull())
	})

	t.Run("x509pop removed server-side is removed from state", func(t *testing.T) {
		model := &ServerGroupResourceModel{
			Attestation: mkAttestation(AttestationModel{
				X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("stale-cert")}),
			}),
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
		require.False(t, model.Attestation.IsNull())
		att := decodeAttestation(t, model.Attestation)
		assert.True(t, att.X509Pop.IsNull(), "x509pop should be cleared once the server no longer reports it")
		require.False(t, att.K8sPsat.IsNull())
		assert.Contains(t, decodeK8sPsat(t, att.K8sPsat).Clusters.Elements(), "cluster-a")
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
			Attestation: mkAttestation(AttestationModel{
				K8sPsat: mkK8sPsat(K8sPsatModel{
					Clusters: mustClustersMap(t, ctx, map[string]K8sPsatClusterModel{
						"cluster-a": clusterA,
						"cluster-b": clusterB,
					}),
				}),
			}),
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
		att := decodeAttestation(t, model.Attestation)
		require.False(t, att.K8sPsat.IsNull())
		clusters := decodeK8sPsat(t, att.K8sPsat).Clusters.Elements()
		assert.Contains(t, clusters, "cluster-a")
		assert.NotContains(t, clusters, "cluster-b", "cluster-b was removed server-side and must not persist in state")
	})

	t.Run("k8s_psat removed server-side is removed from state", func(t *testing.T) {
		emptyCluster := K8sPsatClusterModel{
			ServiceAccountAllowList: types.ListNull(types.StringType),
			Audience:                types.ListNull(types.StringType),
			AllowedPodLabelKeys:     types.ListNull(types.StringType),
			AllowedNodeLabelKeys:    types.ListNull(types.StringType),
		}
		model := &ServerGroupResourceModel{
			Attestation: mkAttestation(AttestationModel{
				X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				K8sPsat: mkK8sPsat(K8sPsatModel{
					Clusters: mustClustersMap(t, ctx, map[string]K8sPsatClusterModel{
						"cluster-a": emptyCluster,
					}),
				}),
			}),
		}
		at := &swaclient.AttestationConfiguration{
			X509pop: &swaclient.X509PopConfigurationInput{CaCertificates: "cert"},
		}

		diags := updateAttestationFromResponse(ctx, model, at)
		assert.False(t, diags.HasError())
		require.False(t, model.Attestation.IsNull())
		att := decodeAttestation(t, model.Attestation)
		assert.True(t, att.K8sPsat.IsNull(), "k8s_psat should be cleared once the server no longer reports it")
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
		require.False(t, model.Attestation.IsNull())
		att := decodeAttestation(t, model.Attestation)
		require.False(t, att.GcpServiceAccount.IsNull())
		assert.True(t, att.X509Pop.IsNull())
		assert.True(t, att.K8sPsat.IsNull())
		gcp := decodeGcpServiceAccount(t, att.GcpServiceAccount)

		var projects []string
		require.False(t, gcp.AllowedProjectIDs.ElementsAs(ctx, &projects, false).HasError())
		assert.Equal(t, []string{"project-a", "project-b"}, projects)

		var auds []string
		require.False(t, gcp.Audiences.ElementsAs(ctx, &auds, false).HasError())
		assert.Equal(t, []string{"urn:panw:swa"}, auds)
	})

	t.Run("gemini_enterprise from attestation field is reconciled into state", func(t *testing.T) {
		model := &ServerGroupResourceModel{}
		audiences := []string{"urn:panw:swa"}
		at := &swaclient.AttestationConfiguration{
			GeminiEnterprise: &swaclient.GeminiEnterpriseAttestationConfiguration{
				AllowedOrgIds: []string{"org-a", "org-b"},
				Audiences:     &audiences,
			},
		}

		diags := updateAttestationFromResponse(ctx, model, at)
		assert.False(t, diags.HasError())
		require.False(t, model.Attestation.IsNull())
		att := decodeAttestation(t, model.Attestation)
		require.False(t, att.GeminiEnterprise.IsNull())
		assert.True(t, att.X509Pop.IsNull())
		assert.True(t, att.K8sPsat.IsNull())
		gemini := decodeGeminiEnterprise(t, att.GeminiEnterprise)

		var orgs []string
		require.False(t, gemini.AllowedOrgIDs.ElementsAs(ctx, &orgs, false).HasError())
		assert.Equal(t, []string{"org-a", "org-b"}, orgs)

		var auds []string
		require.False(t, gemini.Audiences.ElementsAs(ctx, &auds, false).HasError())
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
		require.False(t, model.Attestation.IsNull())
		att := decodeAttestation(t, model.Attestation)
		require.False(t, att.AwsIid.IsNull())
		awsIid := decodeAwsIid(t, att.AwsIid)
		assert.Equal(t, "SWAServerRole", awsIid.AssumeRole.ValueString())
		assert.Equal(t, "aws", awsIid.Partition.ValueString())

		require.False(t, awsIid.VerifyOrganization.IsNull())
		vo := decodeAwsIidVerifyOrg(t, awsIid.VerifyOrganization)
		assert.Equal(t, "123456789012", vo.ManagementAccountID.ValueString())
		assert.Equal(t, "us-east-1", vo.ManagementAccountRegion.ValueString())
		assert.Equal(t, "AWSOrganizationsReadOnlyAccess", vo.AssumeOrgRole.ValueString())
		assert.Equal(t, "15m", vo.OrgAccountMapTTL.ValueString())
		assert.True(t, vo.AccountListFile.IsNull())
	})

	t.Run("k8s_jwt from attestation field is reconciled into state", func(t *testing.T) {
		model := &ServerGroupResourceModel{}
		at := &swaclient.AttestationConfiguration{
			K8sJwt: &swaclient.K8sJwtAttestationConfiguration{
				Clusters: map[string]swaclient.K8sJwtCluster{
					"cluster-a": {
						Issuer:                  "https://kubernetes.default.svc.cluster.local",
						Audience:                "swa-node-attestation",
						ServiceAccountAllowList: []string{"swa-system:swa-agent"},
						JwksUri:                 new("https://oidc.eks.example.com/keys"),
					},
				},
			},
		}

		diags := updateAttestationFromResponse(ctx, model, at)
		assert.False(t, diags.HasError())
		require.False(t, model.Attestation.IsNull())
		att := decodeAttestation(t, model.Attestation)
		require.False(t, att.K8sJwt.IsNull())

		var clusters map[string]K8sJwtClusterModel
		require.False(t, decodeK8sJwt(t, att.K8sJwt).Clusters.ElementsAs(ctx, &clusters, false).HasError())
		require.Contains(t, clusters, "cluster-a")
		cluster := clusters["cluster-a"]
		assert.Equal(t, "https://kubernetes.default.svc.cluster.local", cluster.Issuer.ValueString())
		assert.Equal(t, "swa-node-attestation", cluster.Audience.ValueString())
		assert.Equal(t, "https://oidc.eks.example.com/keys", cluster.JwksUri.ValueString())
		assert.True(t, cluster.PublicKeys.IsNull())

		var sas []string
		require.False(t, cluster.ServiceAccountAllowList.ElementsAs(ctx, &sas, false).HasError())
		assert.Equal(t, []string{"swa-system:swa-agent"}, sas)
	})

	t.Run("k8s_jwt public_keys keeps prior JSON formatting when semantically equal", func(t *testing.T) {
		priorPublicKeys := `{
  "type": "jwks",
  "value": {"keys": [{"kty": "RSA"}]}
}`
		priorClusters := map[string]K8sJwtClusterModel{
			"cluster-a": {
				Issuer:                  types.StringValue("https://issuer.example.com"),
				Audience:                types.StringValue("swa-node-attestation"),
				ServiceAccountAllowList: mustStringList(t, "ns:sa"),
				JwksUri:                 types.StringNull(),
				PublicKeys:              types.StringValue(priorPublicKeys),
			},
		}
		clustersMap, diags := types.MapValueFrom(ctx, types.ObjectType{AttrTypes: k8sJwtClusterAttrTypes()}, priorClusters)
		require.False(t, diags.HasError())
		model := &ServerGroupResourceModel{
			Attestation: mkAttestation(AttestationModel{
				K8sJwt: mkK8sJwt(K8sJwtModel{Clusters: clustersMap}),
			}),
		}

		at := &swaclient.AttestationConfiguration{
			K8sJwt: &swaclient.K8sJwtAttestationConfiguration{
				Clusters: map[string]swaclient.K8sJwtCluster{
					"cluster-a": {
						Issuer:                  "https://issuer.example.com",
						Audience:                "swa-node-attestation",
						ServiceAccountAllowList: []string{"ns:sa"},
						PublicKeys: &swaclient.K8sJwtClusterPublicKeys{
							Type:  new(swaclient.K8sJwtClusterPublicKeysTypeJwks),
							Value: swaclient.K8sJwtJwks{Keys: []swaclient.K8sJwtJwk{{Kty: swaclient.K8sJwtJwkKtyRSA}}},
						},
					},
				},
			},
		}

		updateDiags := updateAttestationFromResponse(ctx, model, at)
		assert.False(t, updateDiags.HasError())

		att := decodeAttestation(t, model.Attestation)
		var clusters map[string]K8sJwtClusterModel
		require.False(t, decodeK8sJwt(t, att.K8sJwt).Clusters.ElementsAs(ctx, &clusters, false).HasError())
		assert.Equal(t, priorPublicKeys, clusters["cluster-a"].PublicKeys.ValueString(), "prior JSON formatting should be preserved when semantically equal")
	})
}

func TestBuildK8sJwtClusters(t *testing.T) {
	ctx := context.Background()

	k8sJwtClusterModel := func(t *testing.T, ctx context.Context, m map[string]K8sJwtClusterModel) types.Map {
		t.Helper()
		objs := make(map[string]attr.Value, len(m))
		for k, v := range m {
			obj, diags := types.ObjectValueFrom(ctx, k8sJwtClusterAttrTypes(), v)
			require.False(t, diags.HasError(), "failed to build cluster object: %v", diags)
			objs[k] = obj
		}
		mapValue, diags := types.MapValue(types.ObjectType{AttrTypes: k8sJwtClusterAttrTypes()}, objs)
		require.False(t, diags.HasError(), "failed to build clusters map: %v", diags)
		return mapValue
	}

	t.Run("nil model returns nil map", func(t *testing.T) {
		clusters, diags := buildK8sJwtClusters(ctx, nil)
		require.Nil(t, clusters)
		assert.False(t, diags.HasError())
	})

	t.Run("null clusters returns nil map", func(t *testing.T) {
		clusters, diags := buildK8sJwtClusters(ctx, &K8sJwtModel{
			Clusters: types.MapNull(types.ObjectType{AttrTypes: k8sJwtClusterAttrTypes()}),
		})
		require.Nil(t, clusters)
		assert.False(t, diags.HasError())
	})

	t.Run("converts jwks_uri cluster", func(t *testing.T) {
		clusters, diags := buildK8sJwtClusters(ctx, &K8sJwtModel{
			Clusters: k8sJwtClusterModel(t, ctx, map[string]K8sJwtClusterModel{
				"cluster-a": {
					Issuer:                  types.StringValue("https://issuer.example.com"),
					Audience:                types.StringValue("swa-node-attestation"),
					ServiceAccountAllowList: mustStringList(t, "ns:sa"),
					JwksUri:                 types.StringValue("https://issuer.example.com/keys"),
					PublicKeys:              types.StringNull(),
				},
			}),
		})

		require.False(t, diags.HasError())
		require.Len(t, clusters, 1)
		cluster := clusters["cluster-a"]
		assert.Equal(t, "https://issuer.example.com", cluster.Issuer)
		assert.Equal(t, "swa-node-attestation", cluster.Audience)
		assert.Equal(t, []string{"ns:sa"}, cluster.ServiceAccountAllowList)
		require.NotNil(t, cluster.JwksUri)
		assert.Equal(t, "https://issuer.example.com/keys", *cluster.JwksUri)
		assert.Nil(t, cluster.PublicKeys)
	})

	t.Run("converts public_keys cluster", func(t *testing.T) {
		clusters, diags := buildK8sJwtClusters(ctx, &K8sJwtModel{
			Clusters: k8sJwtClusterModel(t, ctx, map[string]K8sJwtClusterModel{
				"cluster-a": {
					Issuer:                  types.StringValue("https://issuer.example.com"),
					Audience:                types.StringValue("swa-node-attestation"),
					ServiceAccountAllowList: mustStringList(t, "ns:sa"),
					JwksUri:                 types.StringNull(),
					PublicKeys:              types.StringValue(`{"type":"jwks","value":{"keys":[{"kty":"RSA"}]}}`),
				},
			}),
		})

		require.False(t, diags.HasError())
		require.Len(t, clusters, 1)
		cluster := clusters["cluster-a"]
		require.NotNil(t, cluster.PublicKeys)
		require.Len(t, cluster.PublicKeys.Value.Keys, 1)
		assert.Equal(t, swaclient.K8sJwtJwkKtyRSA, cluster.PublicKeys.Value.Keys[0].Kty)
	})

	t.Run("invalid public_keys JSON reports diagnostics", func(t *testing.T) {
		_, diags := buildK8sJwtClusters(ctx, &K8sJwtModel{
			Clusters: k8sJwtClusterModel(t, ctx, map[string]K8sJwtClusterModel{
				"cluster-a": {
					Issuer:                  types.StringValue("https://issuer.example.com"),
					Audience:                types.StringValue("swa-node-attestation"),
					ServiceAccountAllowList: mustStringList(t, "ns:sa"),
					JwksUri:                 types.StringNull(),
					PublicKeys:              types.StringValue(`not-json`),
				},
			}),
		})
		assert.True(t, diags.HasError())
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

	t.Run("unknown list attributes are omitted like null ones", func(t *testing.T) {
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

		clusters, diags := buildK8sPsatClusters(ctx, &K8sPsatModel{Clusters: clustersMap})
		require.False(t, diags.HasError())
		require.Len(t, clusters, 1)
		assert.Nil(t, clusters["cluster-a"].Audience)
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{
						CaCertificates: types.StringValue("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"),
					}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{
						CaCertificates: types.StringValue("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"),
					}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					GcpServiceAccount: mkGcpServiceAccount(GcpServiceAccountModel{
						AllowedProjectIDs: mustStringList(t, "project-a", "project-b"),
						Audiences:         mustStringList(t, "urn:panw:swa"),
					}),
				}),
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
			// When gemini_enterprise is configured, the request must go out on the
			// attestation API field.
			name: "successful creation with Gemini Enterprise attestation",
			data: ServerGroupResourceModel{
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: mkAttestation(AttestationModel{
					GeminiEnterprise: mkGeminiEnterprise(GeminiEnterpriseModel{
						AllowedOrgIDs: mustStringList(t, "org-a", "org-b"),
						Audiences:     mustStringList(t, "urn:panw:swa"),
					}),
				}),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sg := makeServerGroupResponse("prod-servers", "prod.example.org")
				audiences := []string{"urn:panw:swa"}
				m.On("PostServerGroupWithResponse", context.Background(), "prod.example.org", &swaclient.PostServerGroupParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostServerGroupJSONRequestBody{
					Name: "prod-servers",
					Attestation: &swaclient.AttestationConfiguration{
						GeminiEnterprise: &swaclient.GeminiEnterpriseAttestationConfiguration{
							AllowedOrgIds: []string{"org-a", "org-b"},
							Audiences:     &audiences,
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
				Attestation: mkAttestation(AttestationModel{
					AwsIid: mkAwsIid(AwsIidModel{
						AssumeRole: types.StringValue("SWAServerRole"),
						Partition:  types.StringValue("aws"),
						VerifyOrganization: mkAwsIidVerifyOrg(AwsIidVerifyOrgModel{
							ManagementAccountID: types.StringValue("123456789012"),
							AssumeOrgRole:       types.StringValue("AWSOrganizationsReadOnlyAccess"),
						}),
					}),
				}),
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
				Attestation:     mkAttestation(AttestationModel{}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{
						CaCertificates: types.StringValue("cert"),
					}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{
						CaCertificates: types.StringValue("cert"),
					}),
				}),
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
			normalizeServerGroupModel(&tt.data)
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{
						CaCertificates: types.StringValue("stale-cert"),
					}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{
						CaCertificates: types.StringValue("cert"),
					}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{
						CaCertificates: types.StringValue("cert"),
					}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
			normalizeServerGroupModel(&tt.data)
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
					require.False(t, result.Attestation.IsNull())
					att := decodeAttestation(t, result.Attestation)
					require.False(t, att.X509Pop.IsNull())
					assert.Equal(t, tt.expectedCert, decodeX509Pop(t, att.X509Pop).CaCertificates.ValueString())
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
			normalizeServerGroupModel(&tt.data)
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
			},
			state: ServerGroupResourceModel{
				ID:              types.StringValue("prod.example.org/prod-servers"),
				Name:            types.StringValue("prod-servers"),
				TrustDomainName: types.StringValue("prod.example.org"),
				Description:     types.StringNull(),
				Attestation: mkAttestation(AttestationModel{
					X509Pop: mkX509Pop(X509PopModel{CaCertificates: types.StringValue("cert")}),
				}),
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
			normalizeServerGroupModel(&tt.plan)
			normalizeServerGroupModel(&tt.state)
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

// TestServerGroupResource_ValidateConfig_UnknownGCPServiceAccount guards against the
// bug reported against this resource: HCL like
//
//	attestation = {
//	  gcp_service_account = var.enable_gcp ? { ... } : null
//	}
//
// leaves attestation.gcp_service_account wholly Unknown at validate-time (Terraform
// core can't statically resolve a conditional between an object and null), and
// ValidateConfig used to decode the whole `attestation` block into *AttestationModel in
// one shot, which hard-errored trying to reflect that Unknown value into the plain
// *GcpServiceAccountModel struct. This can't be expressed via a *ServerGroupResourceModel
// Go literal (a struct pointer field has no Unknown state to assign), so
// gcp_service_account is overwritten directly on the raw plan value via SetAttribute,
// mirroring TestServerResource_ValidateConfig_UnknownIdentity.
func TestServerGroupResource_ValidateConfig_UnknownGCPServiceAccount(t *testing.T) {
	data := ServerGroupResourceModel{
		Name:            types.StringValue("test-sg"),
		TrustDomainName: types.StringValue("test-td"),
		Attestation:     mkAttestation(AttestationModel{}),
	}

	gcpAttrTypes := map[string]attr.Type{
		"allowed_project_ids": types.ListType{ElemType: types.StringType},
		"audiences":           types.ListType{ElemType: types.StringType},
	}

	s := getServerGroupTestSchema()
	plan := newPlanWithSchema(s)
	normalizeServerGroupModel(&data)
	require.False(t, plan.Set(context.Background(), &data).HasError())
	require.False(t, plan.SetAttribute(
		context.Background(),
		path.Root("attestation").AtName("gcp_service_account"),
		types.ObjectUnknown(gcpAttrTypes),
	).HasError())

	r := &ServerGroupResource{}
	req := resource.ValidateConfigRequest{
		Config: buildServerConfigFromPlan(plan, s),
	}
	resp := &resource.ValidateConfigResponse{}

	r.ValidateConfig(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
}

// Regression test: creating a gemini_enterprise server group without an explicit
// `audiences` list used to fail with "Provider produced inconsistent result after
// apply", for the same reason as TestServerGroupResource_GcpServiceAccount_DefaultAudienceOmitted:
// the API applies a server-side default (`urn:panw:swa`) that the `audiences` attribute's
// schema didn't mark Computed.
func TestServerGroupResource_GeminiEnterprise_DefaultAudienceOmitted(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	defaultAudiences := []string{"urn:panw:swa"}
	att := &swaclient.AttestationConfiguration{
		GeminiEnterprise: &swaclient.GeminiEnterpriseAttestationConfiguration{
			AllowedOrgIds: []string{"org-a"},
			Audiences:     &defaultAudiences,
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
    gemini_enterprise = {
      allowed_org_ids = ["org-a"]
    }
  }
}
`,
				Check: tfresource.TestCheckResourceAttr(
					"conjur_swa_server_group.test", "attestation.gemini_enterprise.audiences.0", "urn:panw:swa",
				),
			},
		},
	})
}

func TestServerGroupResource_ValidateConfig_RejectsEmptyGeminiAllowedOrgIDs(t *testing.T) {
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
    gemini_enterprise = {
      allowed_org_ids = []
    }
  }
}
`,
				ExpectError: regexp.MustCompile(`(?s)allowed_org_ids.*at\s+least 1`),
			},
		},
	})
}

// TestServerGroupResource_ValidateConfig_UnknownGeminiEnterprise mirrors
// TestServerGroupResource_ValidateConfig_UnknownGCPServiceAccount for the gemini_enterprise
// attestation variant.
func TestServerGroupResource_ValidateConfig_UnknownGeminiEnterprise(t *testing.T) {
	data := ServerGroupResourceModel{
		Name:            types.StringValue("test-sg"),
		TrustDomainName: types.StringValue("test-td"),
		Attestation:     mkAttestation(AttestationModel{}),
	}

	s := getServerGroupTestSchema()
	plan := newPlanWithSchema(s)
	normalizeServerGroupModel(&data)
	require.False(t, plan.Set(context.Background(), &data).HasError())
	require.False(t, plan.SetAttribute(
		context.Background(),
		path.Root("attestation").AtName("gemini_enterprise"),
		types.ObjectUnknown(geminiEnterpriseAttrTypes()),
	).HasError())

	r := &ServerGroupResource{}
	req := resource.ValidateConfigRequest{
		Config: buildServerConfigFromPlan(plan, s),
	}
	resp := &resource.ValidateConfigResponse{}

	r.ValidateConfig(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
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

// TestServerGroupResource_K8sJwt_JwksUri exercises a k8s_jwt cluster configured with
// jwks_uri end to end through the mocked SWA client.
func TestServerGroupResource_K8sJwt_JwksUri(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	att := &swaclient.AttestationConfiguration{
		K8sJwt: &swaclient.K8sJwtAttestationConfiguration{
			Clusters: map[string]swaclient.K8sJwtCluster{
				"cluster-1": {
					Issuer:                  "https://kubernetes.default.svc.cluster.local",
					Audience:                "swa-node-attestation",
					ServiceAccountAllowList: []string{"swa-system:swa-agent"},
					JwksUri:                 new("https://oidc.eks.example.com/keys"),
				},
			},
		},
	}

	mockClient.EXPECT().
		PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything,
			mock.MatchedBy(func(body swaclient.PostServerGroupJSONRequestBody) bool {
				return body.Attestation != nil && reflect.DeepEqual(body.Attestation.K8sJwt, att.K8sJwt)
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
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"
  attestation = {
    k8s_jwt = {
      clusters = {
        "cluster-1" = {
          issuer                      = "https://kubernetes.default.svc.cluster.local"
          audience                    = "swa-node-attestation"
          service_account_allow_list  = ["swa-system:swa-agent"]
          jwks_uri                    = "https://oidc.eks.example.com/keys"
        }
      }
    }
  }
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.k8s_jwt.clusters.cluster-1.issuer", "https://kubernetes.default.svc.cluster.local"),
					tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.k8s_jwt.clusters.cluster-1.audience", "swa-node-attestation"),
					tfresource.TestCheckResourceAttr("conjur_swa_server_group.test", "attestation.k8s_jwt.clusters.cluster-1.jwks_uri", "https://oidc.eks.example.com/keys"),
					tfresource.TestCheckNoResourceAttr("conjur_swa_server_group.test", "attestation.k8s_jwt.clusters.cluster-1.public_keys"),
				),
			},
		},
	})
}

// TestServerGroupResource_K8sJwt_PublicKeys exercises a k8s_jwt cluster configured with
// an inline public_keys JSON document instead of jwks_uri.
func TestServerGroupResource_K8sJwt_PublicKeys(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	att := &swaclient.AttestationConfiguration{
		K8sJwt: &swaclient.K8sJwtAttestationConfiguration{
			Clusters: map[string]swaclient.K8sJwtCluster{
				"cluster-1": {
					Issuer:                  "https://issuer.example.com",
					Audience:                "swa-node-attestation",
					ServiceAccountAllowList: []string{"swa-system:swa-agent"},
					PublicKeys: &swaclient.K8sJwtClusterPublicKeys{
						Type:  new(swaclient.K8sJwtClusterPublicKeysTypeJwks),
						Value: swaclient.K8sJwtJwks{Keys: []swaclient.K8sJwtJwk{{Kty: swaclient.K8sJwtJwkKtyRSA}}},
					},
				},
			},
		},
	}

	mockClient.EXPECT().
		PostServerGroupWithResponse(mock.Anything, "test-td", mock.Anything,
			mock.MatchedBy(func(body swaclient.PostServerGroupJSONRequestBody) bool {
				return body.Attestation != nil && reflect.DeepEqual(body.Attestation.K8sJwt, att.K8sJwt)
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
				Config: `
resource "conjur_swa_server_group" "test" {
  name              = "test-sg"
  trust_domain_name = "test-td"
  attestation = {
    k8s_jwt = {
      clusters = {
        "cluster-1" = {
          issuer                     = "https://issuer.example.com"
          audience                   = "swa-node-attestation"
          service_account_allow_list = ["swa-system:swa-agent"]
          public_keys                = jsonencode({ type = "jwks", value = { keys = [{ kty = "RSA" }] } })
        }
      }
    }
  }
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttrSet("conjur_swa_server_group.test", "attestation.k8s_jwt.clusters.cluster-1.public_keys"),
					tfresource.TestCheckNoResourceAttr("conjur_swa_server_group.test", "attestation.k8s_jwt.clusters.cluster-1.jwks_uri"),
				),
			},
		},
	})
}

// TestServerGroupResource_ValidateConfig_RejectsK8sJwtBothJwksUriAndPublicKeys and
// TestServerGroupResource_ValidateConfig_RejectsK8sJwtNeitherJwksUriNorPublicKeys exercise
// the mutual-exclusivity check in validateK8sJwtClusters.
func TestServerGroupResource_ValidateConfig_RejectsK8sJwtBothJwksUriAndPublicKeys(t *testing.T) {
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
    k8s_jwt = {
      clusters = {
        "cluster-1" = {
          issuer                     = "https://issuer.example.com"
          audience                   = "swa-node-attestation"
          service_account_allow_list = ["swa-system:swa-agent"]
          jwks_uri                   = "https://issuer.example.com/keys"
          public_keys                = jsonencode({ type = "jwks", value = { keys = [{ kty = "RSA" }] } })
        }
      }
    }
  }
}
`,
				ExpectError: regexp.MustCompile(`(?s)only one of jwks_uri or public_keys`),
			},
		},
	})
}

func TestServerGroupResource_ValidateConfig_RejectsK8sJwtNeitherJwksUriNorPublicKeys(t *testing.T) {
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
    k8s_jwt = {
      clusters = {
        "cluster-1" = {
          issuer                     = "https://issuer.example.com"
          audience                   = "swa-node-attestation"
          service_account_allow_list = ["swa-system:swa-agent"]
        }
      }
    }
  }
}
`,
				ExpectError: regexp.MustCompile(`(?s)one of jwks_uri or public_keys must be set`),
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
