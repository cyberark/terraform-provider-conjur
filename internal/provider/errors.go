package provider

import (
	"errors"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// isNotFoundErr reports whether err represents a "not found" condition from the Conjur API.
// conjur-api-go surfaces missing resources as plain errors rather than a typed sentinel, so
// this matches on the message. It is used by resource Read methods to distinguish out-of-band
// deletion (drift, which should remove the resource from state) from genuine errors.
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
