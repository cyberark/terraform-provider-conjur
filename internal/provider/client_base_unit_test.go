package provider

import (
	"context"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	swamocks "github.com/cyberark/terraform-provider-conjur/internal/swa/client/mocks"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Diagnostics for every Configure path are covered by the TestEveryResource* tests in
// capabilities_unit_test.go; these tests cover what ends up in the client field.
func TestBaseProviderComponent_SelectsClient(t *testing.T) {
	t.Run("conjurComponent selects the Conjur client", func(t *testing.T) {
		clients := mockClientsForEnvironment(t, conjurapi.EnvironmentSaaS)
		clients.swaClient = swamocks.NewMockClientWithResponsesInterface(t)
		c := conjurComponent("conjur_issuer", CapabilityIssuersV1)
		var diags diag.Diagnostics

		c.configure(clients, &diags)

		require.False(t, diags.HasError())
		assert.Same(t, clients.conjurClient, c.client)
	})

	t.Run("swaComponent selects the SWA client", func(t *testing.T) {
		clients := mockClientsForEnvironment(t, conjurapi.EnvironmentSaaS)
		mockSWA := swamocks.NewMockClientWithResponsesInterface(t)
		clients.swaClient = mockSWA
		c := swaComponent("conjur_swa_trust_domain", CapabilitySWA)
		var diags diag.Diagnostics

		c.configure(clients, &diags)

		require.False(t, diags.HasError())
		assert.Same(t, mockSWA, c.client)
	})
}

// The per-operation nil-client checks rely on a failed configure leaving the client unset.
func TestBaseProviderComponent_FailedConfigureLeavesClientUnset(t *testing.T) {
	tests := []struct {
		name         string
		providerData func(t *testing.T) any
	}{
		{name: "nil provider data", providerData: func(t *testing.T) any { return nil }},
		{name: "unexpected provider data type", providerData: func(t *testing.T) any { return "not-a-providerClients" }},
		{name: "unsupported capability", providerData: func(t *testing.T) any { return mockClientsForEnvironment(t, conjurapi.EnvironmentOSS) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := conjurComponent("conjur_issuer", CapabilityIssuersV1)
			var diags diag.Diagnostics

			c.configure(tt.providerData(t), &diags)

			assert.Nil(t, c.client)
		})
	}
}

// Metadata must report the constructor's typeName regardless of the provider type name.
func TestComponentBases_Metadata(t *testing.T) {
	t.Run("resource", func(t *testing.T) {
		r := &resourceBase[api.ClientV2]{conjurComponent("conjur_issuer", CapabilityIssuersV1)}
		resp := &resource.MetadataResponse{}

		r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "ignored"}, resp)

		assert.Equal(t, "conjur_issuer", resp.TypeName)
	})

	t.Run("data source", func(t *testing.T) {
		d := &dataSourceBase[api.ClientV2]{conjurComponent("conjur_secret", CapabilityCoreV2)}
		resp := &datasource.MetadataResponse{}

		d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "ignored"}, resp)

		assert.Equal(t, "conjur_secret", resp.TypeName)
	})

	t.Run("ephemeral", func(t *testing.T) {
		e := &ephemeralBase[api.ClientV2]{conjurComponent("conjur_secret", CapabilityCoreV2)}
		resp := &ephemeral.MetadataResponse{}

		e.Metadata(context.Background(), ephemeral.MetadataRequest{ProviderTypeName: "ignored"}, resp)

		assert.Equal(t, "conjur_secret", resp.TypeName)
	})
}
