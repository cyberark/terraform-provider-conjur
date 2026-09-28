package provider

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
)

func TestIsNotFoundErr(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{name: "nil error", err: nil, expected: false},
		{name: "404", err: &response.ConjurError{Code: http.StatusNotFound}, expected: true},
		{name: "other code", err: &response.ConjurError{Code: http.StatusBadRequest}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isNotFoundErr(tt.err))
		})
	}
}

func TestSanitizeServerText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "plain text is unchanged", input: "Forbidden", expected: "Forbidden"},
		{name: "empty text is unchanged", input: "", expected: ""},
		{name: "control characters are replaced", input: "a\r\nb\tc\x1b[31md\x00", expected: "a  b c [31md "},
		{name: "bidi controls are replaced", input: "abc\u202edcba", expected: "abc dcba"},
		{name: "invalid UTF-8 is replaced", input: "a\xffb", expected: "a\uFFFDb"},
		{name: "long text is truncated", input: strings.Repeat("x", maxServerTextLength+1), expected: strings.Repeat("x", maxServerTextLength) + "... (truncated)"},
		{name: "truncation does not split a multi-byte rune", input: strings.Repeat("x", maxServerTextLength-1) + "é", expected: strings.Repeat("x", maxServerTextLength-1) + "... (truncated)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, sanitizeServerText(tt.input))
		})
	}
}

func TestServerErrorDetail(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{name: "Conjur error includes the status code", err: &response.ConjurError{Code: http.StatusBadGateway, Message: "<html>\nBad Gateway</html>"}, expected: "status 502: <html> Bad Gateway</html>"},
		{name: "other errors are sanitized", err: errors.New("dial tcp:\x1b[31m refused"), expected: "dial tcp: [31m refused"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, serverErrorDetail(tt.err))
		})
	}
}
