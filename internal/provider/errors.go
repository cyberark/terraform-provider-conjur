package provider

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// isNotFoundErr reports whether err represents a "not found" condition from the Conjur API.
// conjur-api-go surfaces non-2xx responses as a typed *response.ConjurError carrying the HTTP
// status code, so this matches on Code == 404 rather than on message text. Suitable for use by
// resource Read methods to distinguish out-of-band deletion (drift, which should remove the
// resource from state) from genuine errors.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}

	var conjurErr *response.ConjurError
	if errors.As(err, &conjurErr) {
		return conjurErr.Code == http.StatusNotFound
	}

	return false
}

// isSuccessStatus reports whether an HTTP status code is in the 2xx success range.
func isSuccessStatus(code int) bool {
	return code >= http.StatusOK && code < http.StatusMultipleChoices
}

// maxServerTextLength caps (in bytes) server-supplied text placed into diagnostics, which end up in CI logs.
const maxServerTextLength = 512

// sanitizeServerText makes server-supplied text safe to place into diagnostics: it truncates the text to
// maxServerTextLength bytes, replaces invalid UTF-8, and replaces control and bidirectional formatting
// characters (newlines, ANSI escape sequences, RTL overrides, ...) with spaces.
func sanitizeServerText(s string) string {
	truncated := false
	if len(s) > maxServerTextLength {
		cut := maxServerTextLength
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
		truncated = true
	}

	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD"))

	if truncated {
		s += "... (truncated)"
	}
	return s
}

// maxListedServerIDs caps how many server-supplied IDs are listed in a single diagnostic.
const maxListedServerIDs = 10

// formatServerIDs formats server-supplied IDs for a diagnostic: each ID is sanitized and quoted, and
// at most maxListedServerIDs are listed.
func formatServerIDs(ids []string) string {
	quoted := make([]string, 0, min(len(ids), maxListedServerIDs))
	for _, id := range ids[:min(len(ids), maxListedServerIDs)] {
		quoted = append(quoted, fmt.Sprintf("%q", sanitizeServerText(id)))
	}
	list := strings.Join(quoted, ", ")
	if len(ids) > maxListedServerIDs {
		list += fmt.Sprintf(" and %d more", len(ids)-maxListedServerIDs)
	}
	return list
}

// serverErrorDetail formats an error returned by the Conjur API for a diagnostic. The message is
// sanitized with sanitizeServerText, and the HTTP status code is included when available.
func serverErrorDetail(err error) string {
	var conjurErr *response.ConjurError
	if errors.As(err, &conjurErr) {
		return fmt.Sprintf("status %d: %s", conjurErr.Code, sanitizeServerText(conjurErr.Error()))
	}
	return sanitizeServerText(err.Error())
}

// diagsToError flattens error diagnostics into a single error for helpers that
// return error instead of diag.Diagnostics, or nil when there are none.
func diagsToError(diags diag.Diagnostics) error {
	if !diags.HasError() {
		return nil
	}
	msgs := make([]string, 0, len(diags.Errors()))
	for _, d := range diags.Errors() {
		msgs = append(msgs, fmt.Sprintf("%s: %s", d.Summary(), d.Detail()))
	}
	return errors.New(strings.Join(msgs, "; "))
}
