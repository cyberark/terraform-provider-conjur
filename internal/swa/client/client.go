package client

import (
	"context"
	"net/http"
	"time"
)

//go:generate oapi-codegen --config=openapi-cfg.yaml ../api/openapi.yaml
//go:generate mockery
//go:generate goimports -w client.gen.go

const (
	DefaultTimeout = 30 * time.Second
)

// SWAClient wraps the generated client with authentication
type SWAClient struct {
	*ClientWithResponses
	baseURL     string
	accessToken string
	timeout     time.Duration
}

var _ ClientWithResponsesInterface = (*SWAClient)(nil)

// NewSWAClientWithTransport creates a new SWA API client that delegates
// authentication to the provided http.RoundTripper. This is used with
// AuthTransport to support all conjur-api-go authenticator types
// (API key, JWT, OIDC, IAM, Azure, GCP, cert, etc.) with automatic
// token refresh.
func NewSWAClientWithTransport(baseURL string, transport http.RoundTripper) (*SWAClient, error) {
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
	}

	client, err := NewClientWithResponses(baseURL, WithHTTPClient(httpClient), WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/x.secretsmgr.v2+json")
		return nil
	}))
	if err != nil {
		return nil, err
	}

	return &SWAClient{
		ClientWithResponses: client,
		baseURL:             baseURL,
		timeout:             DefaultTimeout,
	}, nil
}
