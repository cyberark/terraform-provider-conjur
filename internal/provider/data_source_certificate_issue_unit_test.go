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

type mockCertificateIssuer struct {
	mock.Mock
}

func (m *mockCertificateIssuer) CertificateIssue(issuerName string, issue conjurapi.Issue) (*conjurapi.CertificateResponse, error) {
	args := m.Called(issuerName, issue)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*conjurapi.CertificateResponse), args.Error(1)
}

func TestCertificateIssueDataSource_Read(t *testing.T) {
	tests := []struct {
		name               string
		data               certificateIssueDataSourceModel
		setupMock          func(*mockCertificateIssuer)
		expectedError      bool
		errorContains      string
		expectedCert       string
		expectedChainCount int
		expectedPrivateKey string
	}{
		{
			name: "successful certificate issue with minimal fields",
			data: certificateIssueDataSourceModel{
				IssuerName: types.StringValue("test-issuer"),
				CommonName: types.StringValue("example.com"),
				KeyType:    types.StringValue("RSA"),
				TTL:        types.StringValue("24h"),
			},
			setupMock: func(m *mockCertificateIssuer) {
				m.On("CertificateIssue", "test-issuer", mock.MatchedBy(func(issue conjurapi.Issue) bool {
					return issue.Subject.CommonName == "example.com" && issue.KeyType == "RSA"
				})).Return(&conjurapi.CertificateResponse{
					Certificate: "-----BEGIN CERTIFICATE-----\nCert\n-----END CERTIFICATE-----",
					PrivateKey:  "-----BEGIN PRIVATE KEY-----\nPrivateKey\n-----END PRIVATE KEY-----",
					Chain:       []string{"-----BEGIN CERTIFICATE-----\nChainCert\n-----END CERTIFICATE-----"},
				}, nil)
			},
			expectedError:      false,
			expectedCert:       "-----BEGIN CERTIFICATE-----\nCert\n-----END CERTIFICATE-----",
			expectedPrivateKey: "-----BEGIN PRIVATE KEY-----\nPrivateKey\n-----END PRIVATE KEY-----",
			expectedChainCount: 1,
		},
		{
			name: "API error during certificate issue",
			data: certificateIssueDataSourceModel{
				IssuerName: types.StringValue("error-issuer"),
				CommonName: types.StringValue("error.com"),
			},
			setupMock: func(m *mockCertificateIssuer) {
				m.On("CertificateIssue", "error-issuer", mock.Anything).Return(
					nil, fmt.Errorf("invalid parameters"))
			},
			expectedError: true,
			errorContains: "Error issuing certificate",
		},
		{
			name: "issuer not found",
			data: certificateIssueDataSourceModel{
				IssuerName: types.StringValue("nonexistent-issuer"),
				CommonName: types.StringValue("test.com"),
			},
			setupMock: func(m *mockCertificateIssuer) {
				m.On("CertificateIssue", "nonexistent-issuer", mock.Anything).Return(
					nil, fmt.Errorf("404 Not Found"))
			},
			expectedError: true,
			errorContains: "Error issuing certificate",
		},
		{
			name: "issue with all subject fields",
			data: certificateIssueDataSourceModel{
				IssuerName:   types.StringValue("full-issuer"),
				CommonName:   types.StringValue("server.example.com"),
				Organization: types.StringValue("Example Corp"),
				OrgUnits:     []types.String{},
				Locality:     types.StringValue("San Francisco"),
				State:        types.StringValue("California"),
				Country:      types.StringValue("US"),
				KeyType:      types.StringValue("ECDSA"),
				TTL:          types.StringValue("720h"),
			},
			setupMock: func(m *mockCertificateIssuer) {
				m.On("CertificateIssue", "full-issuer", mock.MatchedBy(func(issue conjurapi.Issue) bool {
					return issue.Subject.CommonName == "server.example.com" &&
						issue.Subject.Organization == "Example Corp" &&
						issue.Subject.Locality == "San Francisco" &&
						issue.Subject.State == "California" &&
						issue.Subject.Country == "US"
				})).Return(&conjurapi.CertificateResponse{
					Certificate: "-----BEGIN CERTIFICATE-----\nFullCert\n-----END CERTIFICATE-----",
					PrivateKey:  "-----BEGIN PRIVATE KEY-----\nFullKey\n-----END PRIVATE KEY-----",
					Chain:       []string{},
				}, nil)
			},
			expectedError:      false,
			expectedCert:       "-----BEGIN CERTIFICATE-----\nFullCert\n-----END CERTIFICATE-----",
			expectedPrivateKey: "-----BEGIN PRIVATE KEY-----\nFullKey\n-----END PRIVATE KEY-----",
			expectedChainCount: 0,
		},
		{
			name: "issue with IP addresses",
			data: certificateIssueDataSourceModel{
				IssuerName:  types.StringValue("ip-issuer"),
				CommonName:  types.StringValue("192.168.1.1"),
				IPAddresses: []types.String{},
			},
			setupMock: func(m *mockCertificateIssuer) {
				m.On("CertificateIssue", "ip-issuer", mock.Anything).Return(&conjurapi.CertificateResponse{
					Certificate: "-----BEGIN CERTIFICATE-----\nIPCert\n-----END CERTIFICATE-----",
					PrivateKey:  "-----BEGIN PRIVATE KEY-----\nIPKey\n-----END PRIVATE KEY-----",
					Chain:       []string{},
				}, nil)
			},
			expectedError:      false,
			expectedCert:       "-----BEGIN CERTIFICATE-----\nIPCert\n-----END CERTIFICATE-----",
			expectedPrivateKey: "-----BEGIN PRIVATE KEY-----\nIPKey\n-----END PRIVATE KEY-----",
			expectedChainCount: 0,
		},
		{
			name: "issue with email addresses",
			data: certificateIssueDataSourceModel{
				IssuerName:     types.StringValue("email-issuer"),
				CommonName:     types.StringValue("admin@example.com"),
				EmailAddresses: []types.String{},
			},
			setupMock: func(m *mockCertificateIssuer) {
				m.On("CertificateIssue", "email-issuer", mock.Anything).Return(&conjurapi.CertificateResponse{
					Certificate: "-----BEGIN CERTIFICATE-----\nEmailCert\n-----END CERTIFICATE-----",
					PrivateKey:  "-----BEGIN PRIVATE KEY-----\nEmailKey\n-----END PRIVATE KEY-----",
					Chain:       []string{},
				}, nil)
			},
			expectedError:      false,
			expectedCert:       "-----BEGIN CERTIFICATE-----\nEmailCert\n-----END CERTIFICATE-----",
			expectedPrivateKey: "-----BEGIN PRIVATE KEY-----\nEmailKey\n-----END PRIVATE KEY-----",
			expectedChainCount: 0,
		},
		{
			name: "issue with URIs",
			data: certificateIssueDataSourceModel{
				IssuerName: types.StringValue("uri-issuer"),
				CommonName: types.StringValue("service.example.com"),
				Uris:       []types.String{},
			},
			setupMock: func(m *mockCertificateIssuer) {
				m.On("CertificateIssue", "uri-issuer", mock.Anything).Return(&conjurapi.CertificateResponse{
					Certificate: "-----BEGIN CERTIFICATE-----\nURICert\n-----END CERTIFICATE-----",
					PrivateKey:  "-----BEGIN PRIVATE KEY-----\nURIKey\n-----END PRIVATE KEY-----",
					Chain:       []string{},
				}, nil)
			},
			expectedError:      false,
			expectedCert:       "-----BEGIN CERTIFICATE-----\nURICert\n-----END CERTIFICATE-----",
			expectedPrivateKey: "-----BEGIN PRIVATE KEY-----\nURIKey\n-----END PRIVATE KEY-----",
			expectedChainCount: 0,
		},
		{
			name: "permission denied error",
			data: certificateIssueDataSourceModel{
				IssuerName: types.StringValue("restricted-issuer"),
				CommonName: types.StringValue("restricted.example.com"),
			},
			setupMock: func(m *mockCertificateIssuer) {
				m.On("CertificateIssue", "restricted-issuer", mock.Anything).Return(
					nil, fmt.Errorf("403 Forbidden"))
			},
			expectedError: true,
			errorContains: "Error issuing certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockIssuer := new(mockCertificateIssuer)
			tt.setupMock(mockIssuer)

			d := &certificateIssueDataSource{
				client: mockIssuer,
			}

			testSchema := getCertificateIssueDataSourceTestSchema()

			attrTypes := map[string]tftypes.Type{
				"issuer_name":     tftypes.String,
				"common_name":     tftypes.String,
				"organization":    tftypes.String,
				"org_units":       tftypes.List{ElementType: tftypes.String},
				"locality":        tftypes.String,
				"state":           tftypes.String,
				"country":         tftypes.String,
				"key_type":        tftypes.String,
				"ttl":             tftypes.String,
				"zone":            tftypes.String,
				"dns_names":       tftypes.List{ElementType: tftypes.String},
				"ip_addresses":    tftypes.List{ElementType: tftypes.String},
				"email_addresses": tftypes.List{ElementType: tftypes.String},
				"uris":            tftypes.List{ElementType: tftypes.String},
				"certificate":     tftypes.String,
				"chain":           tftypes.List{ElementType: tftypes.String},
				"private_key":     tftypes.String,
			}

			values := map[string]tftypes.Value{
				"issuer_name":     tftypes.NewValue(tftypes.String, tt.data.IssuerName.ValueString()),
				"common_name":     tftypes.NewValue(tftypes.String, tt.data.CommonName.ValueString()),
				"organization":    tftypes.NewValue(tftypes.String, tt.data.Organization.ValueString()),
				"locality":        tftypes.NewValue(tftypes.String, tt.data.Locality.ValueString()),
				"state":           tftypes.NewValue(tftypes.String, tt.data.State.ValueString()),
				"country":         tftypes.NewValue(tftypes.String, tt.data.Country.ValueString()),
				"key_type":        tftypes.NewValue(tftypes.String, tt.data.KeyType.ValueString()),
				"ttl":             tftypes.NewValue(tftypes.String, tt.data.TTL.ValueString()),
				"zone":            tftypes.NewValue(tftypes.String, tt.data.Zone.ValueString()),
				"org_units":       tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
				"dns_names":       tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
				"ip_addresses":    tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
				"email_addresses": tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
				"uris":            tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
				"certificate":     tftypes.NewValue(tftypes.String, nil),
				"chain":           tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
				"private_key":     tftypes.NewValue(tftypes.String, nil),
			}

			configVal := tftypes.NewValue(tftypes.Object{AttributeTypes: attrTypes}, values)

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
				var result certificateIssueDataSourceModel
				resp.State.Get(ctx, &result)
				assert.Equal(t, tt.data.IssuerName.ValueString(), result.IssuerName.ValueString())
				assert.Equal(t, tt.expectedCert, result.Certificate.ValueString())
				assert.Equal(t, tt.expectedPrivateKey, result.PrivateKey.ValueString())
				assert.Equal(t, tt.expectedChainCount, len(result.Chain))
			}
			mockIssuer.AssertExpectations(t)
		})
	}
}

func getCertificateIssueDataSourceTestSchema() schema.Schema {
	d := &certificateIssueDataSource{}
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
