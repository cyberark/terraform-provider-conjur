package multi_cloud_access_token

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var mockResponse = `{
	"access_token": "mock_access_token"
}`

// Mocking the server response
func createMockServer(response string, statusCode int) *httptest.Server {
	handler := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		w.Write([]byte(response))
	}))
	return handler
}

// Tests the successful token retrieval scenario
func TestAzureTokenProvider_Token_Success(t *testing.T) {
	ts := createMockServer(mockResponse, http.StatusOK)
	defer ts.Close()

	originalAzureBaseURL := AzureBaseURL
	AzureBaseURL = ts.URL + "/metadata/identity/oauth2/token?api-version=2018-02-01"
	defer func() { AzureBaseURL = originalAzureBaseURL }()

	provider := &AzureTokenProvider{}
	token, err := provider.Token("mock-client-id")

	// Verify no error and the token is as expected
	assert.NoError(t, err)
	assert.Equal(t, "mock_access_token", token)
}

// Tests the failure scenario (malformed JSON)
func TestAzureTokenProvider_Token_Failure(t *testing.T) {

	ts := createMockServer(`{ "invalid_json" `, http.StatusOK)
	defer ts.Close()

	originalAzureBaseURL := AzureBaseURL
	AzureBaseURL = ts.URL + "/metadata/identity/oauth2/token?api-version=2018-02-01"
	defer func() { AzureBaseURL = originalAzureBaseURL }()

	provider := &AzureTokenProvider{}
	token, err := provider.Token("mock-client-id")

	// Verify error occurs and token is empty
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestAzureTokenProvider_Token_HTTPRequestFailure(t *testing.T) {
	// Use an invalid URL to simulate request failure
	originalAzureBaseURL := AzureBaseURL
	AzureBaseURL = "http://localhost:0/invalid-url"
	defer func() { AzureBaseURL = originalAzureBaseURL }()

	provider := &AzureTokenProvider{}
	token, err := provider.Token("mock-client-id")

	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestAzureTokenProvider_Token_Non200StatusCode(t *testing.T) {
	ts := createMockServer("{}", http.StatusForbidden)
	defer ts.Close()

	originalAzureBaseURL := AzureBaseURL
	AzureBaseURL = ts.URL + "/metadata/identity/oauth2/token?api-version=2018-02-01"
	defer func() { AzureBaseURL = originalAzureBaseURL }()

	provider := &AzureTokenProvider{}
	token, err := provider.Token("mock-client-id")

	assert.Error(t, err)  // Even if body parses, request failed logically
	assert.Empty(t, token)
}

func TestAzureTokenProvider_Token_EmptyClientID(t *testing.T) {
	ts := createMockServer(mockResponse, http.StatusOK)
	defer ts.Close()

	originalAzureBaseURL := AzureBaseURL
	AzureBaseURL = ts.URL + "/metadata/identity/oauth2/token?api-version=2018-02-01"
	defer func() { AzureBaseURL = originalAzureBaseURL }()

	provider := &AzureTokenProvider{}
	token, err := provider.Token("")

	assert.NoError(t, err)
	assert.Equal(t, "mock_access_token", token)
}

func TestAzureTokenProvider_Token_MissingAccessToken(t *testing.T) {
	ts := createMockServer(`{}`, http.StatusOK)
	defer ts.Close()

	originalAzureBaseURL := AzureBaseURL
	AzureBaseURL = ts.URL + "/metadata/identity/oauth2/token?api-version=2018-02-01"
	defer func() { AzureBaseURL = originalAzureBaseURL }()

	provider := &AzureTokenProvider{}
	token, err := provider.Token("mock-client-id")

	assert.NoError(t, err)
	assert.Empty(t, token) // token is empty but no error during unmarshalling
}

func TestAzureTokenProvider_Token_InvalidBaseURL(t *testing.T) {
	originalAzureBaseURL := AzureBaseURL
	AzureBaseURL = "::::::" // invalid URL
	defer func() { AzureBaseURL = originalAzureBaseURL }()

	provider := &AzureTokenProvider{}
	token, err := provider.Token("mock-client-id")

	assert.Error(t, err)
	assert.Empty(t, token)
}
