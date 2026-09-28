package provider

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
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

// serverErrorDetail formats an error returned by the Conjur API for a diagnostic. The message is
// sanitized with sanitizeServerText, and the HTTP status code is included when available.
func serverErrorDetail(err error) string {
	var conjurErr *response.ConjurError
	if errors.As(err, &conjurErr) {
		return fmt.Sprintf("status %d: %s", conjurErr.Code, sanitizeServerText(conjurErr.Error()))
	}
	return sanitizeServerText(err.Error())
}
