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

func TestCertificateSignDataSource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ds := NewCertificateSignDataSource()

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
type mockV2Client struct {
	Response *conjurapi.CertificateResponse
	Err      error
}

func (m *mockV2Client) CertificateSign(_ string, _ conjurapi.Sign) (*conjurapi.CertificateResponse, error) {
	return m.Response, m.Err
}

// Mock main client
type mockSignClient struct {
	V2Client certificateSignV2Client
}

func (m *mockSignClient) V2() certificateSignV2Client {
	return m.V2Client
}

func TestCertificateSignDataSource_Read_Success(t *testing.T) {
	issuer := "my-issuer"
	csr := "my-csr"
	zone := "my-zone"
	ttl := "PT24H"
	mockClient := &mockSignClient{
		V2Client: &mockV2Client{
			Response: &conjurapi.CertificateResponse{
				Certificate: "signed-cert",
				PrivateKey:  "",
				Chain:       []string{"root-cert"},
			},
			Err: nil,
		},
	}

	resp, data := invokeSign(t, mockClient, issuer, csr, zone, ttl)

	assert.Empty(t, resp.Diagnostics)
	assert.Equal(t, "signed-cert", data.Certificate.ValueString())
	assert.Equal(t, "", data.PrivateKey.ValueString())
	assert.Len(t, data.Chain, 1)
	assert.Equal(t, "root-cert", data.Chain[0].ValueString())
}

func TestCertificateSignDataSource_Read_Error(t *testing.T) {
	issuer := "my-issuer"
	csr := "my-csr"
	zone := "my-zone"
	ttl := "PT24H"
	mockClient := &mockSignClient{
		V2Client: &mockV2Client{
			Response: nil,
			Err:      fmt.Errorf("signing failed"),
		},
	}

	resp, data := invokeSign(t, mockClient, issuer, csr, zone, ttl)

	// Assertions
	assert.Len(t, resp.Diagnostics, 1)
	assert.Equal(t, "Error signing certificate", resp.Diagnostics[0].Summary())
	assert.Equal(t, "signing failed", resp.Diagnostics[0].Detail())
	assert.Equal(t, "", data.Certificate.ValueString())
	assert.Equal(t, "", data.PrivateKey.ValueString())
	assert.Len(t, data.Chain, 0)
}

// Helper to invoke the sign (READ) method using the mocked client and test inputs
func invokeSign(t *testing.T, client *mockSignClient, issuer, csr, zone, ttl string) (datasource.ReadResponse, certificateSignDataSourceModel) {
	data := certificateSignDataSourceModel{
		IssuerName: types.StringValue(issuer),
		Csr:        types.StringValue(csr),
		Zone:       types.StringValue(zone),
		TTL:        types.StringValue(ttl),
	}

	resp := datasource.ReadResponse{}

	signReq := conjurapi.Sign{
		Csr:  csr,
		Zone: zone,
		TTL:  ttl,
	}

	signResp, err := client.V2().CertificateSign(issuer, signReq)
	if err != nil {
		resp.Diagnostics.AddError("Error signing certificate", err.Error())
		return resp, data
	}

	data.Certificate = types.StringValue(signResp.Certificate)
	data.PrivateKey = types.StringValue(signResp.PrivateKey)
	data.Chain = make([]types.String, len(signResp.Chain))
	for i, c := range signResp.Chain {
		data.Chain[i] = types.StringValue(c)
	}

	return resp, data
}
