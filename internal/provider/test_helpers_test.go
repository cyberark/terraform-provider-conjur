package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	apimocks "github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	frameworkschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/mock"
)

// contains reports whether substr is within str.
// Shared across unit test files in this package to avoid duplication.
func contains(str, substr string) bool {
	return strings.Contains(str, substr)
}

func makeHTTPResponse(statusCode int) *http.Response {
	return &http.Response{StatusCode: statusCode}
}

func assertDiagContains(t *testing.T, diags diag.Diagnostics, expectedSubstring string) {
	t.Helper()
	for _, d := range diags.Errors() {
		if contains(d.Summary(), expectedSubstring) || contains(d.Detail(), expectedSubstring) {
			return
		}
	}
	t.Fatalf("expected diagnostics to contain %q", expectedSubstring)
}

func assertWarningContains(t *testing.T, diags diag.Diagnostics, expectedSubstring string) {
	t.Helper()
	for _, d := range diags.Warnings() {
		if contains(d.Summary(), expectedSubstring) || contains(d.Detail(), expectedSubstring) {
			return
		}
	}
	t.Fatalf("expected warning diagnostics to contain %q", expectedSubstring)
}

// newPlanWithSchema creates a tfsdk.Plan initialised with the given schema.
func newPlanWithSchema(s schema.Schema) tfsdk.Plan {
	return tfsdk.Plan{
		Raw:    tftypes.NewValue(tftypes.Object{}, nil),
		Schema: s,
	}
}

// newStateWithSchema creates a tfsdk.State initialised with the given schema.
func newStateWithSchema(s schema.Schema) tfsdk.State {
	return tfsdk.State{
		Raw:    tftypes.NewValue(tftypes.Object{}, nil),
		Schema: s,
	}
}

// swaTestProvider implements provider.Provider with a mock SWA client injected,
// bypassing real Conjur authentication for lifecycle tests.
type swaTestProvider struct {
	t interface {
		mock.TestingT
		Cleanup(func())
	}
	mockClient swaclient.ClientWithResponsesInterface
}

var _ frameworkprovider.Provider = &swaTestProvider{}

func (p *swaTestProvider) Metadata(_ context.Context, _ frameworkprovider.MetadataRequest, resp *frameworkprovider.MetadataResponse) {
	resp.TypeName = "conjur"
	resp.Version = "test"
}

func (p *swaTestProvider) Schema(_ context.Context, _ frameworkprovider.SchemaRequest, resp *frameworkprovider.SchemaResponse) {
	resp.Schema = frameworkschema.Schema{}
}

func (p *swaTestProvider) Configure(_ context.Context, _ frameworkprovider.ConfigureRequest, resp *frameworkprovider.ConfigureResponse) {
	mockConjur := apimocks.NewMockClientV2(p.t)
	mockConjur.On("GetConfig").Return(conjurapi.Config{
		ApplianceURL: "https://myorg-secretsmanager.cyberark.cloud",
		Environment:  conjurapi.EnvironmentSaaS,
	})
	clients := &providerClients{conjurClient: mockConjur, swaClient: p.mockClient}
	resp.ResourceData = clients
}

func (p *swaTestProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewTrustDomainResource,
		NewServerGroupResource,
		NewServerResource,
		NewNodeGroupResource,
	}
}

func (p *swaTestProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// swaTestProviderFactories returns a provider factory that injects mockClient
// into all SWA resources, bypassing real Conjur authentication.
func swaTestProviderFactories(t interface {
	mock.TestingT
	Cleanup(func())
}, mockClient swaclient.ClientWithResponsesInterface) map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"conjur": providerserver.NewProtocol6WithError(&swaTestProvider{t: t, mockClient: mockClient}),
	}
}
