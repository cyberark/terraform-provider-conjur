package provider

import (
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	apimocks "github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureSWAClient_NilProviderData(t *testing.T) {
	req := resource.ConfigureRequest{ProviderData: nil}
	resp := &resource.ConfigureResponse{}

	client, ok := configureSWAClient(req, resp)

	assert.False(t, ok)
	assert.Nil(t, client)
	assert.False(t, resp.Diagnostics.HasError())
}

func TestConfigureSWAClient_WrongType(t *testing.T) {
	req := resource.ConfigureRequest{ProviderData: "not-a-providerClients"}
	resp := &resource.ConfigureResponse{}

	client, ok := configureSWAClient(req, resp)

	assert.False(t, ok)
	assert.Nil(t, client)
	require.True(t, resp.Diagnostics.HasError())
	assertDiagContains(t, resp.Diagnostics, "Unexpected Configure Type")
}

func TestConfigureSWAClient_SelfHostedReturnsError(t *testing.T) {
	mockConjur := apimocks.NewMockClientV2(t)
	mockConjur.On("GetConfig").Return(conjurapi.Config{
		ApplianceURL: "https://conjur.example.com",
		Environment:  conjurapi.EnvironmentSH,
	})

	clients := &providerClients{conjurClient: mockConjur}
	req := resource.ConfigureRequest{ProviderData: clients}
	resp := &resource.ConfigureResponse{}

	client, ok := configureSWAClient(req, resp)

	assert.False(t, ok)
	assert.Nil(t, client)
	require.True(t, resp.Diagnostics.HasError())
	assertDiagContains(t, resp.Diagnostics, "SWA resources require Idira Secrets Manager SaaS")
	assertDiagContains(t, resp.Diagnostics, "Self-Hosted")
}

func TestConfigureSWAClient_OSSReturnsError(t *testing.T) {
	mockConjur := apimocks.NewMockClientV2(t)
	mockConjur.On("GetConfig").Return(conjurapi.Config{
		ApplianceURL: "https://conjur.example.com",
		Environment:  conjurapi.EnvironmentOSS,
	})

	clients := &providerClients{conjurClient: mockConjur}
	req := resource.ConfigureRequest{ProviderData: clients}
	resp := &resource.ConfigureResponse{}

	client, ok := configureSWAClient(req, resp)

	assert.False(t, ok)
	assert.Nil(t, client)
	require.True(t, resp.Diagnostics.HasError())
	assertDiagContains(t, resp.Diagnostics, "SWA resources require Idira Secrets Manager SaaS")
}

func TestConfigureSWAClient_SaaSReturnsClient(t *testing.T) {
	mockConjur := apimocks.NewMockClientV2(t)
	mockConjur.On("GetConfig").Return(conjurapi.Config{
		ApplianceURL: "https://myorg-secretsmanager.cyberark.cloud",
		Environment:  conjurapi.EnvironmentSaaS,
	})

	clients := &providerClients{conjurClient: mockConjur, swaClient: nil}
	req := resource.ConfigureRequest{ProviderData: clients}
	resp := &resource.ConfigureResponse{}

	client, ok := configureSWAClient(req, resp)

	assert.True(t, ok)
	assert.Nil(t, client) // swaClient is nil in this test; the important thing is ok=true and no error
	assert.False(t, resp.Diagnostics.HasError())
}
