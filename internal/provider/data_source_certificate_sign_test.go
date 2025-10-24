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
	CertSignFunc func(issuerName string, sign conjurapi.Sign) (*conjurapi.CertificateResponse, error)
}

func (m *mockV2Client) CertificateSign(issuerName string, sign conjurapi.Sign) (*conjurapi.CertificateResponse, error) {
	return m.CertSignFunc(issuerName, sign)
}

// Mock main client
type mockClient struct {
	V2Func func() certificateSignV2Client
}

func (m *mockClient) V2() certificateSignV2Client {
	return m.V2Func()
}

func TestCertificateSignDataSource_Read_Success(t *testing.T) {
	mockClient := &mockClient{
		V2Func: func() certificateSignV2Client {
			return &mockV2Client{
				CertSignFunc: func(issuerName string, sign conjurapi.Sign) (*conjurapi.CertificateResponse, error) {
					return &conjurapi.CertificateResponse{
						Certificate: "signed-cert",
						PrivateKey:  "",
						Chain:       []string{"root-cert"},
					}, nil
				},
			}
		},
	}

	model := certificateSignDataSourceModel{
		IssuerName: types.StringValue("my-issuer"),
		Csr:        types.StringValue("my-csr"),
		Zone:       types.StringValue("my-zone"),
		TTL:        types.StringValue("24h"),
	}

	resp := &datasource.ReadResponse{}
	dsRead := func() {
		signReq := conjurapi.Sign{
			Csr:  model.Csr.ValueString(),
			Zone: model.Zone.ValueString(),
			TTL:  model.TTL.ValueString(),
		}

		signResp, err := mockClient.V2().CertificateSign(model.IssuerName.ValueString(), signReq)
		if err != nil {
			resp.Diagnostics.AddError("Error signing certificate", err.Error())
			return
		}

		model.Certificate = types.StringValue(signResp.Certificate)
		model.PrivateKey = types.StringValue(signResp.PrivateKey)
		model.Chain = make([]types.String, len(signResp.Chain))
		for i, c := range signResp.Chain {
			model.Chain[i] = types.StringValue(c)
		}
	}

	dsRead()

	assert.Equal(t, "signed-cert", model.Certificate.ValueString())
	assert.Equal(t, "", model.PrivateKey.ValueString())
	assert.Len(t, model.Chain, 1)
	assert.Equal(t, "root-cert", model.Chain[0].ValueString())
}

func TestCertificateSignDataSource_Read_Error(t *testing.T) {
	mockClient := &mockClient{
		V2Func: func() certificateSignV2Client {
			return &mockV2Client{
				CertSignFunc: func(issuerName string, sign conjurapi.Sign) (*conjurapi.CertificateResponse, error) {
					return nil, fmt.Errorf("signing failed")
				},
			}
		},
	}

	model := certificateSignDataSourceModel{
		IssuerName: types.StringValue("my-issuer"),
		Csr:        types.StringValue("my-csr"),
		Zone:       types.StringValue("my-zone"),
		TTL:        types.StringValue("24h"),
	}

	resp := &datasource.ReadResponse{}
	dsRead := func() {
		signReq := conjurapi.Sign{
			Csr:  model.Csr.ValueString(),
			Zone: model.Zone.ValueString(),
			TTL:  model.TTL.ValueString(),
		}

		signResp, err := mockClient.V2().CertificateSign(model.IssuerName.ValueString(), signReq)
		if err != nil {
			resp.Diagnostics.AddError("Error signing certificate", err.Error())
			return
		}

		model.Certificate = types.StringValue(signResp.Certificate)
		model.PrivateKey = types.StringValue(signResp.PrivateKey)
		model.Chain = make([]types.String, len(signResp.Chain))
		for i, c := range signResp.Chain {
			model.Chain[i] = types.StringValue(c)
		}
	}

	dsRead()

	// Assertions
	assert.Len(t, resp.Diagnostics, 1)
	assert.Equal(t, "Error signing certificate", resp.Diagnostics[0].Summary())
	assert.Equal(t, "signing failed", resp.Diagnostics[0].Detail())
	assert.Equal(t, "", model.Certificate.ValueString())
	assert.Equal(t, "", model.PrivateKey.ValueString())
	assert.Len(t, model.Chain, 0)
}
