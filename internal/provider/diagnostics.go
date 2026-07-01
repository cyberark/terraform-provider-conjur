package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// AddProviderClientNotConfiguredWarning adds the standard warning when the provider client
// is not available (e.g., JWT unknown during plan phase in HCP Terraform).
func AddProviderClientNotConfiguredWarning(d *diag.Diagnostics) {
	d.AddWarning(
		"Provider client not configured",
		"The Conjur provider client is not available. This may occur when the JWT token is unknown during the plan phase (e.g., in HCP Terraform). The operation will be skipped.",
	)
}

// AddUnexpectedConfigureTypeError adds an error when the provider data has an unexpected type.
func AddUnexpectedConfigureTypeError(d *diag.Diagnostics, expected string, got interface{}) {
	d.AddError(
		"Unexpected Configure Type",
		fmt.Sprintf("Expected %s, got: %T", expected, got),
	)
}
