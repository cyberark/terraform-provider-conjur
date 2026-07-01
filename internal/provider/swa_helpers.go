package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
)

// configureSWAClient centralizes ProviderData type assertion for SWA resources.
func configureSWAClient(req resource.ConfigureRequest, resp *resource.ConfigureResponse) (swaclient.ClientWithResponsesInterface, bool) {
	if req.ProviderData == nil {
		return nil, false
	}

	clients, ok := req.ProviderData.(*providerClients)
	if !ok {
		// Use the shared diagnostics helper for consistency with other resources.
		AddUnexpectedConfigureTypeError(&resp.Diagnostics, "*providerClients", req.ProviderData)
		return nil, false
	}

	return clients.swaClient, true
}

// optionalStringValue normalizes nullable API string fields for Terraform state.
func optionalStringValue(s *string) types.String {
	if s == nil || *s == "" {
		return types.StringNull()
	}
	return types.StringValue(*s)
}

func apiStatusError(op string, code int, body []byte) (summary, detail string) {
	return fmt.Sprintf("Error %s", op), fmt.Sprintf("API returned status %d: %s", code, string(body))
}

// splitSWAID splits a composite resource ID into exactly expectedParts segments.
// It uses SplitN so that the last segment may itself contain slashes.
func splitSWAID(id string, expectedParts int, format string) ([]string, error) {
	parts := strings.SplitN(id, "/", expectedParts)
	if len(parts) != expectedParts {
		return nil, fmt.Errorf("expected format: %s, got: %s", format, id)
	}
	return parts, nil
}

func optionalStringListValue(ctx context.Context, values *[]string) (types.List, diag.Diagnostics) {
	if values == nil {
		return types.ListNull(types.StringType), nil
	}
	listValue, diags := types.ListValueFrom(ctx, types.StringType, *values)
	return listValue, diags
}

func appendOptionalStringList(ctx context.Context, source *[]string, target *types.List, diags *diag.Diagnostics) {
	listValue, listDiags := optionalStringListValue(ctx, source)
	diags.Append(listDiags...)
	*target = listValue
}
