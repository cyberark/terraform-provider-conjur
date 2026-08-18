package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	apimocks "github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allCapabilities lists every declared Capability. Adding a Capability constant
// without adding it here fails TestCapabilitySupportIsExhaustive.
var allCapabilities = []Capability{
	CapabilityCoreV2,
	CapabilityStaticSecretsV2,
	CapabilityGroupsV2,
	CapabilityIssuersV2,
	CapabilityWorkloadAuthnDescriptors,
	CapabilityBatchSecrets,
	CapabilitySWA,
}

// TestCapabilityEnumIsFullyEnumerated guards allCapabilities against a new
// Capability constant being added to the iota block but not to the slice, which
// would let the other exhaustiveness tests pass while skipping the new entry.
// capabilityCount is the trailing sentinel, so this catches a constant inserted
// anywhere in the block.
func TestCapabilityEnumIsFullyEnumerated(t *testing.T) {
	require.Len(t, allCapabilities, int(capabilityCount),
		"allCapabilities must list every Capability constant; add the new constant to the slice (and keep capabilityCount last)")

	for i, c := range allCapabilities {
		assert.Equal(t, Capability(i), c, "allCapabilities must be in declaration order")
	}
}

// TestCapabilityDefinitionsAreExhaustive merges the old separate support and
// name exhaustiveness tests: the merged capabilities map means both properties
// live in one place and need only one coverage test.
func TestCapabilityDefinitionsAreExhaustive(t *testing.T) {
	for _, c := range allCapabilities {
		def, ok := capabilities[c]
		assert.True(t, ok, "capability %d has no capabilities entry", int(c))
		assert.NotEmpty(t, def.name, "capability %d has an empty name", int(c))
		assert.NotContains(t, c.String(), "Capability(", "capability %d falls back to the numeric name", int(c))
		assert.NotEmpty(t, def.environments, "capability %s is supported on no environment", c)

		for _, env := range def.environments {
			env := env
			assert.Contains(t,
				[]conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS, conjurapi.EnvironmentSH, conjurapi.EnvironmentOSS},
				env, "capability %s lists unknown environment %q", c, env.String())
		}
	}

	assert.Len(t, capabilities, len(allCapabilities),
		"capabilities has entries for capabilities not in allCapabilities")
}

// TestCapabilitySupportMatchesSDK pins the rows whose environments are dictated
// by a hard !IsSaaS() rejection in conjur-api-go. Nothing else asserts these
// values, so without this an incorrect row is invisible - CapabilityBatchSecrets
// was wrongly marked available on Self-Hosted and OSS and no test noticed.
//
// Update a row here only alongside the SDK gate it mirrors, cited per entry.
func TestCapabilitySupportMatchesSDK(t *testing.T) {
	saasOnly := map[Capability]string{
		CapabilityStaticSecretsV2:          "secret_static_v2.go CreateStaticSecret/GetStaticSecretDetails/GetStaticSecretPermissions",
		CapabilityWorkloadAuthnDescriptors: "workload_v2.go CreateWorkload/DeleteWorkload",
		CapabilityIssuersV2:                "issuer_v2.go CertificateIssue/CertificateSign",
		CapabilityBatchSecrets:             "secrets_batch_v2.go BatchRetrieveSecrets",
		CapabilitySWA:                      "SWA is a SaaS-only service",
	}

	for c, sdkGate := range saasOnly {
		assert.Equal(t, []conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS}, capabilities[c].environments,
			"%s must stay SaaS-only: the SDK rejects it off SaaS (%s)", c, sdkGate)
	}
}

// mockClientsForEnvironment builds providerClients whose Conjur config reports env.
func mockClientsForEnvironment(t *testing.T, env conjurapi.EnvironmentType) *providerClients {
	t.Helper()
	mockConjur := apimocks.NewMockClientV2(t)
	mockConjur.On("GetConfig").Return(conjurapi.Config{
		ApplianceURL: "https://conjur.example.com",
		Environment:  env,
	}).Maybe()
	return &providerClients{conjurClient: mockConjur}
}

func TestRequireCapability(t *testing.T) {
	tests := []struct {
		name        string
		environment conjurapi.EnvironmentType
		capability  Capability
		expectError bool
	}{
		{"SWA on SaaS is allowed", conjurapi.EnvironmentSaaS, CapabilitySWA, false},
		{"SWA on Self-Hosted is blocked", conjurapi.EnvironmentSH, CapabilitySWA, true},
		{"SWA on OSS is blocked", conjurapi.EnvironmentOSS, CapabilitySWA, true},
		{"Static secrets on SaaS is allowed", conjurapi.EnvironmentSaaS, CapabilityStaticSecretsV2, false},
		{"Static secrets on Self-Hosted is blocked", conjurapi.EnvironmentSH, CapabilityStaticSecretsV2, true},
		{"Issuers on OSS is blocked", conjurapi.EnvironmentOSS, CapabilityIssuersV2, true},
		{"Core V2 on Self-Hosted is allowed", conjurapi.EnvironmentSH, CapabilityCoreV2, false},
		{"Core V2 on OSS is allowed", conjurapi.EnvironmentOSS, CapabilityCoreV2, false},
		{"Groups on OSS is allowed", conjurapi.EnvironmentOSS, CapabilityGroupsV2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clients := mockClientsForEnvironment(t, tt.environment)

			diags := requireCapability(clients, tt.capability, "conjur_example")

			if !tt.expectError {
				assert.False(t, diags.HasError(), "expected no error, got: %v", diags.Errors())
				return
			}

			require.True(t, diags.HasError())
			assertDiagContains(t, diags, "conjur_example")
			assertDiagContains(t, diags, tt.capability.String())
			env := tt.environment
			assertDiagContains(t, diags, env.FullName())
		})
	}
}

// requireCapability must not block when the environment cannot be determined:
// a nil client is the plan-time unresolved-JWT case, and an empty Environment
// only arises from hand-built configs (conjurapi.Config.Validate rejects it).
func TestRequireCapability_UndeterminedEnvironmentIsAllowed(t *testing.T) {
	t.Run("nil providerClients", func(t *testing.T) {
		diags := requireCapability(nil, CapabilitySWA, "conjur_swa_server")
		assert.Empty(t, diags)
	})

	t.Run("nil conjur client", func(t *testing.T) {
		diags := requireCapability(&providerClients{}, CapabilitySWA, "conjur_swa_server")
		assert.Empty(t, diags)
	})

	t.Run("empty environment", func(t *testing.T) {
		mockConjur := apimocks.NewMockClientV2(t)
		mockConjur.On("GetConfig").Return(conjurapi.Config{ApplianceURL: "https://conjur.example.com"})

		diags := requireCapability(&providerClients{conjurClient: mockConjur}, CapabilitySWA, "conjur_swa_server")

		assert.Empty(t, diags)
	})
}

// An unregistered capability is a provider bug; fail closed rather than allow.
func TestRequireCapability_UnknownCapabilityFailsClosed(t *testing.T) {
	clients := mockClientsForEnvironment(t, conjurapi.EnvironmentSaaS)

	diags := requireCapability(clients, Capability(9999), "conjur_example")

	require.True(t, diags.HasError())
	assertDiagContains(t, diags, "no support matrix entry")
}

func TestConfigureProviderClients(t *testing.T) {
	t.Run("nil provider data is not an error", func(t *testing.T) {
		var diags diag.Diagnostics

		clients, ok := configureProviderClients(nil, CapabilitySWA, "conjur_swa_server", &diags)

		assert.False(t, ok)
		assert.Nil(t, clients)
		assert.False(t, diags.HasError())
	})

	t.Run("wrong provider data type errors", func(t *testing.T) {
		var diags diag.Diagnostics

		clients, ok := configureProviderClients("not-a-providerClients", CapabilitySWA, "conjur_swa_server", &diags)

		assert.False(t, ok)
		assert.Nil(t, clients)
		require.True(t, diags.HasError())
		assertDiagContains(t, diags, "Unexpected Configure Type")
	})

	t.Run("unsupported capability errors without returning clients", func(t *testing.T) {
		var diags diag.Diagnostics
		clients := mockClientsForEnvironment(t, conjurapi.EnvironmentSH)

		got, ok := configureProviderClients(clients, CapabilitySWA, "conjur_swa_server", &diags)

		assert.False(t, ok)
		assert.Nil(t, got)
		require.True(t, diags.HasError())
	})

	t.Run("supported capability returns clients", func(t *testing.T) {
		var diags diag.Diagnostics
		clients := mockClientsForEnvironment(t, conjurapi.EnvironmentSaaS)

		got, ok := configureProviderClients(clients, CapabilitySWA, "conjur_swa_server", &diags)

		assert.True(t, ok)
		assert.Same(t, clients, got)
		assert.False(t, diags.HasError())
	})
}

func TestEnvironmentNames(t *testing.T) {
	tests := []struct {
		name string
		envs []conjurapi.EnvironmentType
		want string
	}{
		{"none", nil, "no supported environment"},
		{"one", []conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS}, "Idira Secrets Manager, SaaS"},
		{
			"two",
			[]conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS, conjurapi.EnvironmentSH},
			"Idira Secrets Manager, SaaS or Idira Secrets Manager, Self-Hosted",
		},
		{
			"three",
			[]conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS, conjurapi.EnvironmentSH, conjurapi.EnvironmentOSS},
			"Idira Secrets Manager, SaaS, Idira Secrets Manager, Self-Hosted or Conjur Open Source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, environmentNames(tt.envs))
		})
	}
}

// gatedResource describes one registered resource, data source or ephemeral
// resource and the capability it is expected to be gated on.
type gatedResource struct {
	// typeName is the Terraform type name, used to assert the diagnostic names
	// the right resource.
	typeName string
	// capability is the gate the resource must enforce.
	capability Capability
	// configure runs the resource's Configure with the given ProviderData and
	// returns the resulting diagnostics.
	configure func(providerData any) diag.Diagnostics
}

func resourceUnderTest(typeName string, capability Capability, newResource func() resource.Resource) gatedResource {
	return gatedResource{
		typeName:   typeName,
		capability: capability,
		configure: func(providerData any) diag.Diagnostics {
			r, ok := newResource().(resource.ResourceWithConfigure)
			if !ok {
				var diags diag.Diagnostics
				diags.AddError("not configurable", fmt.Sprintf("%s does not implement ResourceWithConfigure", typeName))
				return diags
			}
			resp := &resource.ConfigureResponse{}
			r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: providerData}, resp)
			return resp.Diagnostics
		},
	}
}

func dataSourceUnderTest(typeName string, capability Capability, newDataSource func() datasource.DataSource) gatedResource {
	return gatedResource{
		typeName:   typeName,
		capability: capability,
		configure: func(providerData any) diag.Diagnostics {
			d, ok := newDataSource().(datasource.DataSourceWithConfigure)
			if !ok {
				var diags diag.Diagnostics
				diags.AddError("not configurable", fmt.Sprintf("%s does not implement DataSourceWithConfigure", typeName))
				return diags
			}
			resp := &datasource.ConfigureResponse{}
			d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: providerData}, resp)
			return resp.Diagnostics
		},
	}
}

func ephemeralUnderTest(typeName string, capability Capability, newEphemeral func() ephemeral.EphemeralResource) gatedResource {
	return gatedResource{
		typeName:   typeName,
		capability: capability,
		configure: func(providerData any) diag.Diagnostics {
			e, ok := newEphemeral().(ephemeral.EphemeralResourceWithConfigure)
			if !ok {
				var diags diag.Diagnostics
				diags.AddError("not configurable", fmt.Sprintf("%s does not implement EphemeralResourceWithConfigure", typeName))
				return diags
			}
			resp := &ephemeral.ConfigureResponse{}
			e.Configure(context.Background(), ephemeral.ConfigureRequest{ProviderData: providerData}, resp)
			return resp.Diagnostics
		},
	}
}

// gatedResources enumerates every registered resource, data source and ephemeral
// resource together with its expected capability. A newly registered resource
// must be added here or TestEveryResourceDeclaresACapability fails.
func gatedResources() []gatedResource {
	return []gatedResource{
		resourceUnderTest("conjur_authenticator", CapabilityCoreV2, NewAuthenticatorResource),
		resourceUnderTest("conjur_host", CapabilityWorkloadAuthnDescriptors, NewHostResource),
		resourceUnderTest("conjur_group", CapabilityGroupsV2, NewGroupResource),
		resourceUnderTest("conjur_permission", CapabilityCoreV2, NewPermissionResource),
		resourceUnderTest("conjur_membership", CapabilityGroupsV2, NewMembershipResource),
		resourceUnderTest("conjur_secret", CapabilityStaticSecretsV2, NewSecretResource),
		resourceUnderTest("conjur_policy_branch", CapabilityCoreV2, NewPolicyBranchResource),
		resourceUnderTest("conjur_swa_trust_domain", CapabilitySWA, NewTrustDomainResource),
		resourceUnderTest("conjur_swa_server_group", CapabilitySWA, NewServerGroupResource),
		resourceUnderTest("conjur_swa_server", CapabilitySWA, NewServerResource),
		resourceUnderTest("conjur_swa_node_group", CapabilitySWA, NewNodeGroupResource),

		dataSourceUnderTest("conjur_secret", CapabilityCoreV2, NewSecretDataSource),
		dataSourceUnderTest("conjur_certificate_issue", CapabilityIssuersV2, NewCertificateIssueDataSource),
		dataSourceUnderTest("conjur_certificate_sign", CapabilityIssuersV2, NewCertificateSignDataSource),

		ephemeralUnderTest("conjur_secret", CapabilityCoreV2, NewEphemeralSecretResource),
	}
}

// TestGatedResourcesCoversRegistry fails when a resource, data source or
// ephemeral resource is registered in provider.go without a gatedResources
// entry, so capability gating cannot be forgotten for new resources.
func TestGatedResourcesCoversRegistry(t *testing.T) {
	p := &providerImpl{version: "test"}
	ctx := context.Background()

	registered := 0
	registered += len(p.Resources(ctx))
	registered += len(p.DataSources(ctx))
	registered += len(p.EphemeralResources(ctx))

	assert.Len(t, gatedResources(), registered,
		"every registered resource/data source/ephemeral resource needs a gatedResources entry in capabilities_unit_test.go")
}

// TestEveryResourceDeclaresACapability is the table-driven acceptance test for
// gating: it configures each resource against a Self-Hosted deployment and
// asserts either a clean diagnostic or a clean pass, with no API call made. The
// mock is strict - MockClientV2 fails the test on any unexpected call - so
// reaching the network here is itself a failure.
func TestEveryResourceDeclaresACapability(t *testing.T) {
	for _, gr := range gatedResources() {
		t.Run(fmt.Sprintf("%s/%s", gr.typeName, gr.capability), func(t *testing.T) {
			clients := mockClientsForEnvironment(t, conjurapi.EnvironmentSH)
			supportedOnSH := false
			for _, env := range capabilities[gr.capability].environments {
				if env == conjurapi.EnvironmentSH {
					supportedOnSH = true
					break
				}
			}

			diags := gr.configure(clients)

			if supportedOnSH {
				assert.False(t, diags.HasError(),
					"%s declares %s, which is supported on Self-Hosted, so Configure must succeed: %v",
					gr.typeName, gr.capability, diags.Errors())
				return
			}

			require.True(t, diags.HasError(),
				"%s declares %s, which is unsupported on Self-Hosted, so Configure must produce an error",
				gr.typeName, gr.capability)
			assertDiagContains(t, diags, gr.typeName)
			assertDiagContains(t, diags, gr.capability.String())
			assertDiagContains(t, diags, "Self-Hosted")
		})
	}
}

// Configure must stay a no-op when the provider was never configured, so the
// nil-client contract (unresolved JWT at plan time) keeps working.
func TestEveryResourceToleratesNilProviderData(t *testing.T) {
	for _, gr := range gatedResources() {
		t.Run(gr.typeName, func(t *testing.T) {
			diags := gr.configure(nil)
			assert.False(t, diags.HasError(), "expected no error for nil ProviderData: %v", diags.Errors())
		})
	}
}

// Every gated entry must reject a wrong-typed ProviderData rather than panic.
func TestEveryResourceRejectsUnexpectedProviderData(t *testing.T) {
	for _, gr := range gatedResources() {
		t.Run(gr.typeName, func(t *testing.T) {
			diags := gr.configure("not-a-providerClients")
			require.True(t, diags.HasError())
			assertDiagContains(t, diags, "Unexpected Configure Type")
		})
	}
}

// SaaS supports every capability the provider currently declares, so no
// registered resource may refuse to configure against it.
func TestEveryResourceConfiguresOnSaaS(t *testing.T) {
	for _, gr := range gatedResources() {
		t.Run(gr.typeName, func(t *testing.T) {
			clients := mockClientsForEnvironment(t, conjurapi.EnvironmentSaaS)

			diags := gr.configure(clients)

			assert.False(t, diags.HasError(), "expected no error on SaaS: %v", diags.Errors())
		})
	}
}
