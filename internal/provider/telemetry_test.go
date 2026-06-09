package provider

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const conjurTelemetryHeader = "x-cybr-telemetry"

func decodeTelemetry(t *testing.T, encoded string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err, "telemetry header must be valid base64url")
	return string(b)
}

func TestTelemetryData_FieldsAreSet(t *testing.T) {
	assert.Equal(t, "Terraform Provider", telemetryData.IntegrationName)
	assert.Equal(t, "idira-secretsmanager", telemetryData.IntegrationType)
	assert.Equal(t, "Idira", telemetryData.VendorName)
}

func TestTelemetryData_VersionMatchesIntegrationVersion(t *testing.T) {
	assert.Equal(t, IntegrationVersion, telemetryData.IntegrationVersion,
		"telemetryData version must match IntegrationVersion ldflag variable")
}

func TestTelemetryHeader_SentOnRequest(t *testing.T) {
	var capturedHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get(conjurTelemetryHeader)
		if strings.HasSuffix(r.URL.Path, "/authenticate") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("fake-token"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := conjurapi.NewClientFromKey(
		conjurapi.Config{
			Account:           "myorg",
			ApplianceURL:      server.URL,
			CredentialStorage: conjurapi.CredentialStorageNone,
		},
		authn.LoginPair{Login: "admin", APIKey: "secret"},
		telemetryData,
	)
	require.NoError(t, err)

	// Trigger any request so the header is captured by the test server.
	// RetrieveSecret will hit /secrets/... which carries the header.
	_, _ = client.RetrieveSecret("some/secret")

	require.NotEmpty(t, capturedHeader, "x-cybr-telemetry header must be present on requests")
	decoded := decodeTelemetry(t, capturedHeader)
	assert.Contains(t, decoded, "in=Terraform Provider")
	assert.Contains(t, decoded, "it=idira-secretsmanager")
	assert.Contains(t, decoded, "vn=Idira")
}
