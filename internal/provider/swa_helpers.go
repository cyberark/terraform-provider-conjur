package provider

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// swaResourceNamePattern mirrors the charset every SWA resource name path
// parameter shares in openapi.yaml (trust domain, server group, server): 1-60
// characters, letters, numbers, periods, underscores, and hyphens only.
var swaResourceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

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

// splitSWAID splits a composite resource ID into exactly expectedParts segments.
// It uses SplitN so that the last segment may itself contain slashes.
func splitSWAID(id string, expectedParts int, format string) ([]string, error) {
	parts := strings.SplitN(id, "/", expectedParts)
	if len(parts) != expectedParts {
		return nil, fmt.Errorf("expected format: %s, got: %s", format, id)
	}
	return parts, nil
}
