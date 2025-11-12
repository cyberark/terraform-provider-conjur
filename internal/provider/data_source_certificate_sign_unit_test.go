package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockCertificateSigner struct {
	mock.Mock
}

func (m *mockCertificateSigner) CertificateSign(issuerName string, sign conjurapi.Sign) (*conjurapi.CertificateResponse, error) {
	args := m.Called(issuerName, sign)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*conjurapi.CertificateResponse), args.Error(1)
}

func TestCertificateSignDataSource_Read(t *testing.T) {
	tests := []struct {
		name               string
		data               certificateSignDataSourceModel
		setupMock          func(*mockCertificateSigner)
		expectedError      bool
		errorContains      string
		expectedCert       string
		expectedChainCount int
	}{
		{
			name: "successful certificate signing",
			data: certificateSignDataSourceModel{
				IssuerName: types.StringValue("test-issuer"),
				Csr:        types.StringValue("-----BEGIN CERTIFICATE REQUEST-----\nCert\n-----END CERTIFICATE REQUEST-----"),
				Zone:       types.StringValue(""),
				TTL:        types.StringValue("24h"),
			},
			setupMock: func(m *mockCertificateSigner) {
				m.On("CertificateSign", "test-issuer", mock.MatchedBy(func(sign conjurapi.Sign) bool {
					return sign.TTL == "24h"
				})).Return(&conjurapi.CertificateResponse{
					Certificate: "-----BEGIN CERTIFICATE-----\nCert\n-----END CERTIFICATE-----",
					Chain:       []string{"-----BEGIN CERTIFICATE-----\nChainCert\n-----END CERTIFICATE-----"},
					PrivateKey:  "",
				}, nil)
			},
			expectedError:      false,
			expectedCert:       "-----BEGIN CERTIFICATE-----\nCert\n-----END CERTIFICATE-----",
			expectedChainCount: 1,
		},
		{
			name: "API error during signing",
			data: certificateSignDataSourceModel{
				IssuerName: types.StringValue("error-issuer"),
				Csr:        types.StringValue("-----BEGIN CERTIFICATE REQUEST-----\nInvalidCSR\n-----END CERTIFICATE REQUEST-----"),
				Zone:       types.StringValue(""),
				TTL:        types.StringValue(""),
			},
			setupMock: func(m *mockCertificateSigner) {
				m.On("CertificateSign", "error-issuer", mock.Anything).Return(
					nil, fmt.Errorf("invalid CSR format"))
			},
			expectedError: true,
			errorContains: "Error signing certificate",
		},
		{
			name: "issuer not found",
			data: certificateSignDataSourceModel{
				IssuerName: types.StringValue("nonexistent-issuer"),
				Csr:        types.StringValue("-----BEGIN CERTIFICATE REQUEST-----\nValidCSR\n-----END CERTIFICATE REQUEST-----"),
				Zone:       types.StringValue(""),
				TTL:        types.StringValue(""),
			},
			setupMock: func(m *mockCertificateSigner) {
				m.On("CertificateSign", "nonexistent-issuer", mock.Anything).Return(
					nil, fmt.Errorf("404 Not Found"))
			},
			expectedError: true,
			errorContains: "Error signing certificate",
		},
		{
			name: "permission denied error",
			data: certificateSignDataSourceModel{
				IssuerName: types.StringValue("restricted-issuer"),
				Csr:        types.StringValue("-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----"),
				Zone:       types.StringValue(""),
				TTL:        types.StringValue(""),
			},
			setupMock: func(m *mockCertificateSigner) {
				m.On("CertificateSign", "restricted-issuer", mock.Anything).Return(
					nil, fmt.Errorf("403 Forbidden"))
			},
			expectedError: true,
			errorContains: "Error signing certificate",
		},
		{
			name: "signing with minimal parameters",
			data: certificateSignDataSourceModel{
				IssuerName: types.StringValue("simple-issuer"),
				Csr:        types.StringValue("-----BEGIN CERTIFICATE REQUEST-----\nSimpleCSR\n-----END CERTIFICATE REQUEST-----"),
				Zone:       types.StringValue(""),
				TTL:        types.StringValue(""),
			},
			setupMock: func(m *mockCertificateSigner) {
				m.On("CertificateSign", "simple-issuer", mock.MatchedBy(func(sign conjurapi.Sign) bool {
					return sign.Zone == "" && sign.TTL == ""
				})).Return(&conjurapi.CertificateResponse{
					Certificate: "-----BEGIN CERTIFICATE-----\nSimpleCert\n-----END CERTIFICATE-----",
					Chain:       []string{},
					PrivateKey:  "",
				}, nil)
			},
			expectedError:      false,
			expectedCert:       "-----BEGIN CERTIFICATE-----\nSimpleCert\n-----END CERTIFICATE-----",
			expectedChainCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSigner := new(mockCertificateSigner)
			tt.setupMock(mockSigner)

			d := &certificateSignDataSource{
				client: mockSigner,
			}

			testSchema := getCertificateSignDataSourceTestSchema()

			configVal := tftypes.NewValue(
				tftypes.Object{
					AttributeTypes: map[string]tftypes.Type{
						"issuer_name": tftypes.String,
						"csr":         tftypes.String,
						"zone":        tftypes.String,
						"ttl":         tftypes.String,
						"certificate": tftypes.String,
						"chain":       tftypes.List{ElementType: tftypes.String},
						"private_key": tftypes.String,
					},
				},
				map[string]tftypes.Value{
					"issuer_name": tftypes.NewValue(tftypes.String, tt.data.IssuerName.ValueString()),
					"csr":         tftypes.NewValue(tftypes.String, tt.data.Csr.ValueString()),
					"zone":        tftypes.NewValue(tftypes.String, tt.data.Zone.ValueString()),
					"ttl":         tftypes.NewValue(tftypes.String, tt.data.TTL.ValueString()),
					"certificate": tftypes.NewValue(tftypes.String, nil),
					"chain":       tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
					"private_key": tftypes.NewValue(tftypes.String, nil),
				},
			)

			req := datasource.ReadRequest{
				Config: tfsdk.Config{
					Raw:    configVal,
					Schema: testSchema,
				},
			}
			resp := &datasource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: testSchema,
				},
			}

			ctx := context.Background()

			d.Read(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if contains(diag.Summary(), tt.errorContains) || contains(diag.Detail(), tt.errorContains) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error to contain: %s", tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
				var result certificateSignDataSourceModel
				resp.State.Get(ctx, &result)
				assert.Equal(t, tt.data.IssuerName.ValueString(), result.IssuerName.ValueString())
				assert.Equal(t, tt.expectedCert, result.Certificate.ValueString())
				assert.Equal(t, tt.expectedChainCount, len(result.Chain))
			}
			mockSigner.AssertExpectations(t)
		})
	}
}

func getCertificateSignDataSourceTestSchema() schema.Schema {
	d := &certificateSignDataSource{}
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
