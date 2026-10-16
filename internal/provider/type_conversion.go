package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// mapAsStringMap converts a types.Map to a map[string]string, returning nil
// without touching diagnostics if the value is null or unknown (nothing to
// convert yet - see ValidateNonBlank for why null/unknown aren't errors here).
// Any diagnostics from the element conversion are appended to diagnostics.
func mapAsStringMap(ctx context.Context, m types.Map, diagnostics *diag.Diagnostics) map[string]string {
	if m.IsNull() || m.IsUnknown() {
		return nil
	}
	var result map[string]string
	diagnostics.Append(m.ElementsAs(ctx, &result, false)...)
	return result
}

// listAsStrings is the types.List counterpart to mapAsStringMap.
func listAsStrings(ctx context.Context, l types.List, diagnostics *diag.Diagnostics) []string {
	if l.IsNull() || l.IsUnknown() {
		return nil
	}
	var result []string
	diagnostics.Append(l.ElementsAs(ctx, &result, false)...)
	return result
}

// optionalStringValue normalizes nullable API string fields for Terraform state.
func optionalStringValue(s *string) types.String {
	if s == nil || *s == "" {
		return types.StringNull()
	}
	return types.StringValue(*s)
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

// Helper functions to ensure properly handling of null/unknown/unset values
func valueStringPtr(v types.String) *string {
	if !isSet(v) {
		return nil
	}
	return v.ValueStringPointer()
}

func valueBoolPtr(v types.Bool) *bool {
	if !isSet(v) {
		return nil
	}
	return v.ValueBoolPointer()
}

func stringOrNull(s *string) types.String {
	if s != nil {
		return types.StringValue(*s)
	}
	return types.StringNull()
}

func boolOrNull(b *bool) types.Bool {
	if b != nil {
		return types.BoolValue(*b)
	}
	return types.BoolNull()
}

func nonEmptyKnownStringValue(v types.String) bool {
	return isSet(v) && v.ValueString() != ""
}

func stringPointerFromValue(v types.String) *string {
	if !isSet(v) {
		return nil
	}
	return new(v.ValueString())
}
