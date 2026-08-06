package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

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

	cfg := clients.conjurClient.GetConfig()
	if !cfg.IsSaaS() {
		resp.Diagnostics.AddError(
			"SWA resources require Idira Secrets Manager SaaS",
			"SWA resources (conjur_swa_*) are only supported against Idira Secrets Manager SaaS "+
				"endpoints. The configured appliance URL does not appear to be a SaaS instance. "+
				"Remove any conjur_swa_* resources from your configuration when targeting a Self-Hosted deployment.",
		)
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

// doSWARequest triages a SWA API response's status code against the codes
// that count as success for op. On a mismatch it appends the standard
// apiStatusError diagnostic and returns false; callers should return
// immediately in that case. It does not inspect the response body or handle
// transport-level errors — callers check those before calling doSWARequest.
func doSWARequest(op string, statusCode int, body []byte, diags *diag.Diagnostics, want ...int) bool {
	for _, w := range want {
		if statusCode == w {
			return true
		}
	}
	summary, detail := apiStatusError(op, statusCode, body)
	diags.AddError(summary, detail)
	return false
}

// requireSWAResponseBody reports whether body is non-nil. On nil it appends
// the standard "No response body" diagnostic and returns false; callers
// should return immediately in that case.
func requireSWAResponseBody[T any](op string, body *T, diags *diag.Diagnostics) bool {
	if body == nil {
		diags.AddError(fmt.Sprintf("Error %s", op), "No response body")
		return false
	}
	return true
}

// modelFromObject deserializes obj into a new *M, or returns nil (without
// adding diagnostics) when obj is null or unknown.
func modelFromObject[M any](ctx context.Context, obj types.Object, diags *diag.Diagnostics) *M {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var model M
	diags.Append(obj.As(ctx, &model, basetypes.ObjectAsOptions{})...)
	return &model
}

// applyOptionalModel deserializes obj into an *M via modelFromObject and, when
// present, passes it to apply. It reports true when the caller should
// continue: obj was null/unknown (nothing to apply), or apply ran
// successfully. It reports false when decoding obj added an error to diags,
// in which case callers should return immediately, matching the doSWARequest
// / requireSWAResponseBody convention.
func applyOptionalModel[M any](ctx context.Context, obj types.Object, diags *diag.Diagnostics, apply func(*M)) bool {
	model := modelFromObject[M](ctx, obj, diags)
	if diags.HasError() {
		return false
	}
	if model != nil {
		apply(model)
	}
	return true
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
