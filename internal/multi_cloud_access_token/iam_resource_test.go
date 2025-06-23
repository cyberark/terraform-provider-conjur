package multi_cloud_access_token

import (
	"testing"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
)

// Test validAWSAccountNumber function
func TestValidAWSAccountNumber(t *testing.T) {
	tests := []struct {
		hostID   string
		expected bool
	}{
		// Valid AWS Account Numbers
		{"instance/601277729239/role", true},
		{"instance/987654321098/role", true},

		// Invalid AWS Account Numbers
		{"instance/12345678/role/xyz", false},
		{"instance/9876543/role/xyz", false},
		{"instance/123456789012345/role/xyz", false},

		// Invalid format
		{"instance//role/xyz", false},
		{"instance/123456789012", false},
	}

	for _, test := range tests {
		t.Run(test.hostID, func(t *testing.T) {
			result := validAWSAccountNumber(test.hostID)
			if result != test.expected {
				t.Errorf("For hostID %v, expected %v but got %v", test.hostID, test.expected, result)
			}
		})
	}
}

// Test getAWSRegion function
func TestGetAWSRegion(t *testing.T) {
	expected := "us-east-1"
	result := getAWSRegion()

	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

// Test getIAMRoleName function
func TestGetIAMRoleName(t *testing.T) {
	token := "mock-token"
	role := "mock-role"

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(token))
	}))
	defer tokenServer.Close()

	roleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-aws-ec2-metadata-token") != token {
			t.Errorf("Expected metadata token header to be set")
		}
		w.Write([]byte(role))
	}))
	defer roleServer.Close()

	AWSTokenURL = tokenServer.URL
	AWSMetadataURL = roleServer.URL

	result, err := getIAMRoleName()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result != role {
		t.Errorf("Expected role %s, got %s", role, result)
	}
}

// Test getIAMRoleMetadata function
func TestGetIAMRoleMetadata_Success(t *testing.T) {
	role := "mock-role"
	token := "mock-token"
	mockCreds := map[string]string{
		"AccessKeyId":     "AKIA123456789",
		"SecretAccessKey": "secret",
		"Token":           "session-token",
	}
	body, _ := json.Marshal(mockCreds)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, role) {
			t.Errorf("Expected URL to contain role name")
		}
		w.Write(body)
	}))
	defer server.Close()

	AWSMetadataURL = server.URL + "/"

	accessKey, secretKey, sessToken, err := getIAMRoleMetadata(role, token)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if accessKey != mockCreds["AccessKeyId"] || secretKey != mockCreds["SecretAccessKey"] || sessToken != mockCreds["Token"] {
		t.Errorf("Mismatch in credentials returned")
	}
}

// Test createCanonicalRequest function
func TestCreateCanonicalRequest(t *testing.T) {
	amzDate := "20000400T000000Z"
	token := "dummy-token"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
	payloadHash := "e3b0xxxxxfc1c149aae41e4649b934ca495991b7852b855"

	canonical := createCanonicalRequest(amzDate, token, signedHeaders, payloadHash)

	if !strings.Contains(canonical, "x-amz-security-token:dummy-token") {
		t.Errorf("Expected canonical request to include token")
	}
}

// Test IAMTokenProvider Token
func TestIAMTokenProvider_Token(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			w.Write([]byte("mock-token"))
		}
	}))
	defer tokenServer.Close()

	roleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-aws-ec2-metadata-token") != "mock-token" {
			t.Errorf("Expected correct metadata token header")
		}
		w.Write([]byte("mock-role"))
	}))
	defer roleServer.Close()
	
	creds := map[string]string{
		"AccessKeyId":     "AKIAEXAMPLE",
		"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/QWEDEFRGVBGE",
		"Token":           "AWERDfE4o3QWEGR...",
	}
	credsBody, _ := json.Marshal(creds)

	credsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(credsBody)
	}))
	defer credsServer.Close()

	AWSTokenURL = tokenServer.URL
	AWSMetadataURL = credsServer.URL + "/"

	provider := &IAMTokenProvider{}
	apiKey, err := provider.Token("")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !strings.Contains(apiKey, "AKIAEXAMPLE") {
		t.Errorf("Expected API key to contain AccessKeyId")
	}
}
