package provider

import (
	"net/http"
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
