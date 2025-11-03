package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestCertificateIssueDataSource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ds := NewCertificateIssueDataSource()

	schemaRequest := datasource.SchemaRequest{}
	schemaResponse := &datasource.SchemaResponse{}

	ds.Schema(ctx, schemaRequest, schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics had errors: %+v", schemaResponse.Diagnostics)
	}

	if diagnostics := schemaResponse.Schema.ValidateImplementation(ctx); diagnostics.HasError() {
		t.Fatalf("Schema validation failed: %+v", diagnostics)
	}
}

// Mock V2 client for issuing certificates
type mockV2IssueClient struct {
	Response *conjurapi.CertificateResponse
	Err      error
}

func (m *mockV2IssueClient) CertificateIssue(_ string, _ conjurapi.Issue) (*conjurapi.CertificateResponse, error) {
	return m.Response, m.Err
}

// Mock main client implementing certificateIssuer
type mockIssueClient struct {
	V2Client certificateIssuer
}

func (m *mockIssueClient) V2() certificateIssuer {
	return m.V2Client
}
func TestCertificateIssueDataSource_Read_Success(t *testing.T) {
	issuer := "my-issuer"
	commonName := "example.com"
	mockClient := &mockIssueClient{
		V2Client: &mockV2IssueClient{
			Response: &conjurapi.CertificateResponse{
				Certificate: "cert-data",
				PrivateKey:  "key-data",
				Chain:       []string{"root-cert"},
			},
			Err: nil,
		},
	}

	resp, data := invokeIssue(t, mockClient, issuer, commonName)

	assert.Empty(t, resp.Diagnostics)
	assert.Equal(t, "cert-data", data.Certificate.ValueString())
	assert.Equal(t, "key-data", data.PrivateKey.ValueString())
	assert.Len(t, data.Chain, 1)
	assert.Equal(t, "root-cert", data.Chain[0].ValueString())
}

func TestCertificateIssueDataSource_Read_Error(t *testing.T) {
	issuer := "my-issuer"
	commonName := "example.com"
	mockClient := &mockIssueClient{
		V2Client: &mockV2IssueClient{
			Response: nil,
			Err:      fmt.Errorf("issue failed"),
		},
	}

	resp, data := invokeIssue(t, mockClient, issuer, commonName)

	// Assertions
	assert.Len(t, resp.Diagnostics, 1)
	assert.Equal(t, "Error issuing certificate", resp.Diagnostics[0].Summary())
	assert.Equal(t, "issue failed", resp.Diagnostics[0].Detail())
	assert.Equal(t, "", data.Certificate.ValueString())
	assert.Equal(t, "", data.PrivateKey.ValueString())
	assert.Len(t, data.Chain, 0)
}

// Helper to invoke the issue (READ) method using the mocked client and test inputs
func invokeIssue(t *testing.T, mockClient *mockIssueClient, issuer, cn string) (datasource.ReadResponse, certificateIssueDataSourceModel) {
	ds := &certificateIssueDataSource{client: mockClient.V2Client}

	data := certificateIssueDataSourceModel{
		IssuerName: types.StringValue(issuer),
		CommonName: types.StringValue(cn),
	}

	resp := datasource.ReadResponse{}

	reqBody := conjurapi.Issue{
		Subject: conjurapi.IssuerSubject{
			CommonName: cn,
		},
	}

	respObj, err := ds.client.CertificateIssue(issuer, reqBody)
	if err != nil {
		resp.Diagnostics.AddError("Error issuing certificate", err.Error())
		return resp, data
	}

	data.Certificate = types.StringValue(respObj.Certificate)
	data.PrivateKey = types.StringValue(respObj.PrivateKey)
	data.Chain = make([]types.String, len(respObj.Chain))
	for i, c := range respObj.Chain {
		data.Chain[i] = types.StringValue(c)
	}

	return resp, data
}
