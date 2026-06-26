package provider

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
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
