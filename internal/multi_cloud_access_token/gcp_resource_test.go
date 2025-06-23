package multi_cloud_access_token

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Mocking the metadata server response
func mockMetadataServer(t *testing.T) *httptest.Server {
	handler := http.NewServeMux()
	handler.HandleFunc("/instance/service-accounts/default/identity", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Fatalf("Expected Metadata-Flavor header to be 'Google', but got %v", r.Header.Get("Metadata-Flavor"))
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "mock-identity-token")
	})

	return httptest.NewServer(handler)
}

// Unit test for GetIdentityToken function
func TestGetIdentityToken(t *testing.T) {
	mockServer := mockMetadataServer(t)
	defer mockServer.Close()

	baseURL = mockServer.URL + "/instance/service-accounts/default/identity"

	identity, err := GetIdentityToken("dummy_token", "dummy_hostId")
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	expectedIdentity := "mock-identity-token"
	if identity != expectedIdentity {
		t.Fatalf("Expected identity to be '%v', but got '%v'", expectedIdentity, identity)
	}
}

// Unit test for GCPTokenProvider Token method
func TestGCPTokenProvider_Token(t *testing.T) {
	mockServer := mockMetadataServer(t)
	defer mockServer.Close()

	baseURL = mockServer.URL + "/instance/service-accounts/default/identity"

	provider := &GCPTokenProvider{}

	identity, err := provider.Token("")
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	expectedIdentity := "mock-identity-token"
	if identity != expectedIdentity {
		t.Fatalf("Expected identity to be '%v', but got '%v'", expectedIdentity, identity)
	}
}

func TestGetIdentityToken_SpecialCharacters(t *testing.T) {
	mockServer := mockMetadataServer(t)
	defer mockServer.Close()

	baseURL = mockServer.URL + "/instance/service-accounts/default/identity"

	// Using special characters to validate encoding
	_, err := GetIdentityToken("dummy@token", "dummy/host:id")
	if err != nil {
		t.Fatalf("Expected no error with special characters, but got %v", err)
	}
}

func TestGetIdentityToken_Non200Response(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusForbidden)  // Simulate 403 Forbidden error
        fmt.Fprint(w, "Access denied")
    }))
    defer server.Close()

    baseURL = server.URL

    token, err := GetIdentityToken("dummy_token", "dummy_hostId")

    if err == nil {
        t.Fatal("Expected error due to non-200 response, but got none")
    }
    if token != "" {
        t.Fatalf("Expected empty token due to failure, got: %v", token)
    }
}
