package provider

import (
	"context"

	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

type baseProviderComponent[C any] struct {
	typeName       string
	capability     Capability
	clientSelector func(clients *providerClients) C
	client         C
}

func (b *baseProviderComponent[C]) configure(providerData any, diags *diag.Diagnostics) {
	clients, ok := configureProviderClients(providerData, b.capability, b.typeName, diags)
	if !ok {
		return
	}
	b.client = b.clientSelector(clients)
}

func conjurComponent(typeName string, c Capability) baseProviderComponent[api.ClientV2] {
	return baseProviderComponent[api.ClientV2]{
		typeName:   typeName,
		capability: c,
		clientSelector: func(clients *providerClients) api.ClientV2 {
			return clients.conjurClient
		},
	}
}

func swaComponent(typeName string, c Capability) baseProviderComponent[swaclient.ClientWithResponsesInterface] {
	return baseProviderComponent[swaclient.ClientWithResponsesInterface]{
		typeName:   typeName,
		capability: c,
		clientSelector: func(clients *providerClients) swaclient.ClientWithResponsesInterface {
			return clients.swaClient
		},
	}
}

type resourceBase[C any] struct {
	baseProviderComponent[C]
}

func (r *resourceBase[C]) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.typeName
}

func (r *resourceBase[C]) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req.ProviderData, &resp.Diagnostics)
}

type dataSourceBase[C any] struct {
	baseProviderComponent[C]
}

func (d *dataSourceBase[C]) Metadata(_ context.Context, _ datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = d.typeName
}

func (d *dataSourceBase[C]) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.configure(req.ProviderData, &resp.Diagnostics)
}

type ephemeralBase[C any] struct {
	baseProviderComponent[C]
}

func (e *ephemeralBase[C]) Metadata(_ context.Context, _ ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = e.typeName
}

func (e *ephemeralBase[C]) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	e.configure(req.ProviderData, &resp.Diagnostics)
}
