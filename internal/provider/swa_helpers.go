package provider

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// swaResourceNamePattern mirrors the charset every SWA resource name path
// parameter shares in openapi.yaml (trust domain, server group, server): 1-60
// characters, letters, numbers, periods, underscores, and hyphens only.
var swaResourceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

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
	if slices.Contains(want, statusCode) {
		return true
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

// optionalStringListValue normalizes a nullable, possibly-empty API list field into a
// Terraform list value. The API represents "not configured" as either a nil pointer or
// a non-nil pointer to an empty slice; since the corresponding schema attribute is
// Optional (not Computed), the provider must collapse both to null so it never writes
// a value that diverges from what an omitted-in-config attribute planned to.
func optionalStringListValue(ctx context.Context, values *[]string) (types.List, diag.Diagnostics) {
	if values == nil || len(*values) == 0 {
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

// isSet reports whether v holds a configured value, i.e. is neither null nor
// unknown. Request builders use it to omit unset Optional+Computed attributes
// so the server applies its own defaults.
func isSet(v attr.Value) bool {
	return !v.IsNull() && !v.IsUnknown()
}

// int32PtrFromInt64 returns nil for unset values (see isSet).
func int32PtrFromInt64(v types.Int64) *int32 {
	if !isSet(v) {
		return nil
	}
	return new(int32(v.ValueInt64()))
}

// float64Ptr returns nil for unset values (see isSet).
func float64Ptr(v types.Float64) *float64 {
	if !isSet(v) {
		return nil
	}
	return v.ValueFloat64Pointer()
}

// changedPtr returns plan unless it is unset or equals state. PATCH builders
// use it to send only the values that differ from the prior state.
func changedPtr[T comparable](plan, state *T) *T {
	if plan == nil || (state != nil && *plan == *state) {
		return nil
	}
	return plan
}
