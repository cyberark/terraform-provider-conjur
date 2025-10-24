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

// Mock V2 client
type mockV2IssueClient struct {
	CertIssueFunc func(issuerName string, issue conjurapi.Issue) (*conjurapi.CertificateResponse, error)
}

func (m *mockV2IssueClient) CertificateIssue(issuerName string, issue conjurapi.Issue) (*conjurapi.CertificateResponse, error) {
	return m.CertIssueFunc(issuerName, issue)
}

// Mock client implementing certificateIssueClient
type mockIssueClient struct {
	V2Func func() certificateIssueV2Client
}

func (m *mockIssueClient) V2() certificateIssueV2Client {
	return m.V2Func()
}

func TestCertificateIssueDataSource_Read_Success(t *testing.T) {
	mockClient := &mockIssueClient{
		V2Func: func() certificateIssueV2Client {
			return &mockV2IssueClient{
				CertIssueFunc: func(issuerName string, issue conjurapi.Issue) (*conjurapi.CertificateResponse, error) {
					assert.Equal(t, "my-issuer", issuerName)
					assert.Equal(t, "example.com", issue.Subject.CommonName)
					return &conjurapi.CertificateResponse{
						Certificate: "cert-data",
						PrivateKey:  "key-data",
						Chain:       []string{"root-cert"},
					}, nil
				},
			}
		},
	}

	ds := &certificateIssueDataSource{client: mockClient}

	model := certificateIssueDataSourceModel{
		IssuerName: types.StringValue("my-issuer"),
		CommonName: types.StringValue("example.com"),
	}

	// Prepare a fake ReadResponse
	resp := &datasource.ReadResponse{}
	resp.Diagnostics.Append(nil)

	subject := conjurapi.IssuerSubject{
		CommonName: model.CommonName.ValueString(),
	}
	reqBody := conjurapi.Issue{
		Subject: subject,
	}

	respObj, err := ds.client.V2().CertificateIssue(model.IssuerName.ValueString(), reqBody)
	assert.NoError(t, err)

	model.Certificate = types.StringValue(respObj.Certificate)
	model.PrivateKey = types.StringValue(respObj.PrivateKey)
	model.Chain = make([]types.String, len(respObj.Chain))
	for i, c := range respObj.Chain {
		model.Chain[i] = types.StringValue(c)
	}

	assert.Equal(t, "cert-data", model.Certificate.ValueString())
	assert.Equal(t, "key-data", model.PrivateKey.ValueString())
	assert.Len(t, model.Chain, 1)
	assert.Equal(t, "root-cert", model.Chain[0].ValueString())
}

func TestCertificateIssueDataSource_Read_Error(t *testing.T) {
	// Mock the V2 client for certificate issuance
	mockClient := &mockIssueClient{
		V2Func: func() certificateIssueV2Client {
			return &mockV2IssueClient{
				CertIssueFunc: func(issuerName string, issue conjurapi.Issue) (*conjurapi.CertificateResponse, error) {
					return nil, fmt.Errorf("issue failed")
				},
			}
		},
	}

	// Instantiate the datasource with the mock client
	ds := &certificateIssueDataSource{client: mockClient}

	// Input model simulating the Terraform config
	model := certificateIssueDataSourceModel{
		IssuerName: types.StringValue("my-issuer"),
		CommonName: types.StringValue("example.com"),
	}

	// Create a ReadResponse to capture Diagnostics and state
	resp := &datasource.ReadResponse{}

	// Wrap Read call to populate diagnostics/state
	dsRead := func() {
		var data certificateIssueDataSourceModel
		data = model

		subject := conjurapi.IssuerSubject{
			CommonName: model.CommonName.ValueString(),
		}

		reqBody := conjurapi.Issue{
			Subject: subject,
		}

		respObj, err := ds.client.V2().CertificateIssue(model.IssuerName.ValueString(), reqBody)
		if err != nil {
			resp.Diagnostics.AddError("Error issuing certificate", err.Error())
			return
		}

		data.Certificate = types.StringValue(respObj.Certificate)
		data.PrivateKey = types.StringValue(respObj.PrivateKey)
		data.Chain = make([]types.String, len(respObj.Chain))
		for i, c := range respObj.Chain {
			data.Chain[i] = types.StringValue(c)
		}

		resp.Diagnostics.Append(resp.State.Set(context.Background(), &data)...)
	}

	dsRead()

	// Assertions
	assert.Len(t, resp.Diagnostics, 1)
	assert.Equal(t, "Error issuing certificate", resp.Diagnostics[0].Summary())
	assert.Equal(t, "issue failed", resp.Diagnostics[0].Detail())
	assert.Equal(t, "", model.Certificate.ValueString())
	assert.Equal(t, "", model.PrivateKey.ValueString())
	assert.Len(t, model.Chain, 0)
}
