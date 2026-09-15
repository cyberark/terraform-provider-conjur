package provider

import (
	"errors"
	"net/http"

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
