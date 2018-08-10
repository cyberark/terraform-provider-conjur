package main

import (
	"github.com/cyberark/terraform-provider-conjur/conjur"
	"github.com/hashicorp/terraform/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: conjur.Provider,
	})
}
