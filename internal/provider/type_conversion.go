package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
