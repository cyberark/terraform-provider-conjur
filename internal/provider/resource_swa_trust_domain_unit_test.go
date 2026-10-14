package provider

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
	swamocks "github.com/cyberark/terraform-provider-conjur/internal/swa/client/mocks"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func makeTrustDomainResponse() *swaclient.TrustDomainResponse {
	return &swaclient.TrustDomainResponse{
		Name:      "prod.example.org",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Jwt: swaclient.JWTConfiguration{
			SignatureAlgorithm: "RS512",
			SigningKeyType:     "RSA_4096",
			SigningKeyTtl:      86400,
			TokenTtl:           300,
		},
		X509: swaclient.X509Configuration{
			WorkloadTtl: 3600,
		},
	}
}

func getTrustDomainSchema() schema.Schema {
	r := &TrustDomainResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}

// nullJWTObject and nullX509Object are well-typed null objects for test data where
// those attributes are intentionally absent. types.Object{} (zero value) has no
// AttrTypes and causes a type-mismatch when the framework marshals it into a plan.
var (
	nullJWTObject  = types.ObjectNull(jwtAttrTypes)
	nullX509Object = types.ObjectNull(x509AttrTypes)
)

// mustJWTObject builds a types.Object for JWT config in tests, panicking on error.
func mustJWTObject(ctx context.Context, sigAlg, keyType string, signingKeyTTL, tokenTTL int64) types.Object {
	obj, diags := types.ObjectValueFrom(ctx, jwtAttrTypes, &JWTConfigModel{
		SignatureAlgorithm: types.StringValue(sigAlg),
		SigningKeyType:     types.StringValue(keyType),
		SigningKeyTTL:      types.Int64Value(signingKeyTTL),
		TokenTTL:           types.Int64Value(tokenTTL),
	})
	if diags.HasError() {
		panic(fmt.Sprintf("mustJWTObject: %v", diags))
	}
	return obj
}

// mustObject builds a types.Object from a model, panicking on error.
func mustObject(ctx context.Context, attrTypes map[string]attr.Type, model any) types.Object {
	obj, diags := types.ObjectValueFrom(ctx, attrTypes, model)
	if diags.HasError() {
		panic(fmt.Sprintf("mustObject: %v", diags))
	}
	return obj
}

// mustX509Object builds an x509 object that sets only workload_ttl.
func mustX509Object(ctx context.Context, workloadTTL int64) types.Object {
	return mustObject(ctx, x509AttrTypes, &X509ConfigModel{
		WorkloadTTL:                types.Int64Value(workloadTTL),
		IntermediateCertificateTTL: types.Int64Null(),
		IntermediateKeyAlgorithm:   types.StringNull(),
		CA:                         types.ObjectNull(x509CAAttrTypes),
	})
}

// planFromModel encodes a model into a tfsdk.Plan (Plan.Set is the simplest
// way to produce a raw value), for tests that need a plan, config or state.
func planFromModel(t *testing.T, s schema.Schema, model TrustDomainResourceModel) tfsdk.Plan {
	t.Helper()
	ctx := context.Background()
	p := tfsdk.Plan{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	require.False(t, p.Set(ctx, &model).HasError())
	return p
}

// fullX509Model is an x509 block with every certificate attribute set.
func fullX509Model() X509ConfigModel {
	ctx := context.Background()
	cfg, diags := types.ObjectValueFrom(ctx, x509CAConfigAttrTypes, &X509CAConfigModel{
		RootCATTL:                   types.Int64Value(20736000),
		RootKeyAlgorithm:            types.StringValue("RSA_4096"),
		RootRotationTriggerFraction: types.Float64Value(0.8),
	})
	if diags.HasError() {
		panic(fmt.Sprintf("fullX509Model: %v", diags))
	}
	return X509ConfigModel{
		WorkloadTTL:                types.Int64Value(3600),
		IntermediateCertificateTTL: types.Int64Value(172800),
		IntermediateKeyAlgorithm:   types.StringValue("EC_P384"),
		CA:                         mustObject(ctx, x509CAAttrTypes, X509CAModel{Type: types.StringValue("builtin"), Config: cfg}),
	}
}

// fullX509CAInput is the request body expected for fullX509Model's ca block.
func fullX509CAInput() *swaclient.X509CAConfigurationInput {
	return &swaclient.X509CAConfigurationInput{
		Type: swaclient.CATypeBuiltin,
		Config: &swaclient.BuiltinRootCAConfigurationInput{
			RootCaTtl:                   new(int32(20736000)),
			RootKeyAlgorithm:            new(swaclient.CAKeyAlgorithmRSA4096),
			RootRotationTriggerFraction: new(0.8),
		},
	}
}

func TestTrustDomainResource_X509StateFromResponse(t *testing.T) {
	ctx := context.Background()

	t.Run("maps certificate and CA configuration", func(t *testing.T) {
		td := makeTrustDomainResponse()
		td.X509 = swaclient.X509Configuration{
			WorkloadTtl:                3600,
			IntermediateCertificateTtl: new(int32(172800)),
			IntermediateKeyAlgorithm:   new(swaclient.CAKeyAlgorithmECP384),
			Ca: &swaclient.X509CAConfiguration{
				Type: swaclient.CATypeBuiltin,
				Config: swaclient.BuiltinRootCAConfiguration{
					RootCaTtl:                   20736000,
					RootKeyAlgorithm:            swaclient.CAKeyAlgorithmRSA4096,
					RootRotationTriggerFraction: 0.8,
				},
			},
		}

		var model TrustDomainResourceModel
		diags := setTrustDomainStateFromResponse(ctx, &model, td)
		require.False(t, diags.HasError(), "%v", diags)

		var x509 X509ConfigModel
		require.False(t, model.X509.As(ctx, &x509, basetypes.ObjectAsOptions{}).HasError())
		assert.Equal(t, int64(172800), x509.IntermediateCertificateTTL.ValueInt64())
		assert.Equal(t, "EC_P384", x509.IntermediateKeyAlgorithm.ValueString())

		var ca X509CAModel
		require.False(t, x509.CA.As(ctx, &ca, basetypes.ObjectAsOptions{}).HasError())
		assert.Equal(t, "builtin", ca.Type.ValueString())

		var cfg X509CAConfigModel
		require.False(t, ca.Config.As(ctx, &cfg, basetypes.ObjectAsOptions{}).HasError())
		assert.Equal(t, int64(20736000), cfg.RootCATTL.ValueInt64())
		assert.Equal(t, "RSA_4096", cfg.RootKeyAlgorithm.ValueString())
		assert.InDelta(t, 0.8, cfg.RootRotationTriggerFraction.ValueFloat64(), 1e-9)
	})

	t.Run("absent optional fields become null", func(t *testing.T) {
		var model TrustDomainResourceModel
		diags := setTrustDomainStateFromResponse(ctx, &model, makeTrustDomainResponse())
		require.False(t, diags.HasError(), "%v", diags)

		var x509 X509ConfigModel
		require.False(t, model.X509.As(ctx, &x509, basetypes.ObjectAsOptions{}).HasError())
		assert.True(t, x509.IntermediateCertificateTTL.IsNull())
		assert.True(t, x509.IntermediateKeyAlgorithm.IsNull())
		assert.True(t, x509.CA.IsNull())
	})
}

func TestTrustDomainResource_ValidateConfig(t *testing.T) {
	ctx := context.Background()
	s := getTrustDomainSchema()

	withTTLs := func(workloadTTL, intermediateTTL int64) types.Object {
		m := fullX509Model()
		m.WorkloadTTL = types.Int64Value(workloadTTL)
		m.IntermediateCertificateTTL = types.Int64Value(intermediateTTL)
		return mustObject(ctx, x509AttrTypes, &m)
	}

	tests := []struct {
		name          string
		x509          types.Object
		errorContains string
	}{
		{name: "valid TTL relationship", x509: mustObject(ctx, x509AttrTypes, func() *X509ConfigModel { m := fullX509Model(); return &m }())},
		{name: "intermediate TTL equal to twice workload TTL", x509: withTTLs(43200, 86400)},
		{
			name:          "intermediate TTL below twice workload TTL",
			x509:          withTTLs(86400, 86400),
			errorContains: "intermediate_certificate_ttl must be at least twice workload_ttl",
		},
		{name: "unset values are left to the server", x509: mustX509Object(ctx, 86400)},
		{name: "no x509 block", x509: nullX509Object},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := planFromModel(t, s, TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: tt.x509,
			})
			cfg := tfsdk.Config{Schema: s, Raw: plan.Raw}
			var resp resource.ValidateConfigResponse
			(&TrustDomainResource{}).ValidateConfig(ctx, resource.ValidateConfigRequest{Config: cfg}, &resp)

			if tt.errorContains == "" {
				assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
				return
			}
			require.True(t, resp.Diagnostics.HasError())
			assert.Contains(t, resp.Diagnostics.Errors()[0].Detail(), tt.errorContains)
		})
	}
}

func TestTrustDomainResource_Create(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		data          TrustDomainResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful creation with name only",
			data: TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse()
				m.On("PostTrustDomainWithResponse", ctx, &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostTrustDomainJSONRequestBody{Name: "prod.example.org"}).
					Return(&swaclient.PostTrustDomainResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
						ApplicationxSecretsmgrV2JSON201: td,
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful creation with JWT config",
			data: TrustDomainResourceModel{
				Name: types.StringValue("dev.example.org"),
				JWT:  mustJWTObject(ctx, "ES256", "EC_P256", 3600, 600),
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse()
				td.Name = "dev.example.org"
				sigAlg := swaclient.JWTConfigurationInputSignatureAlgorithm("ES256")
				keyType := swaclient.JWTConfigurationInputSigningKeyType("EC_P256")
				signingKeyTTL := int32(3600)
				tokenTTL := int32(600)
				m.On("PostTrustDomainWithResponse", ctx, &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostTrustDomainJSONRequestBody{
					Name: "dev.example.org",
					Jwt: &swaclient.JWTConfigurationInput{
						SignatureAlgorithm: &sigAlg,
						SigningKeyType:     &keyType,
						SigningKeyTtl:      &signingKeyTTL,
						TokenTtl:           &tokenTTL,
					},
				}).Return(&swaclient.PostTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: td,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful creation with X509 config",
			data: TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustX509Object(ctx, 7200),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse()
				workloadTTL := int32(7200)
				m.On("PostTrustDomainWithResponse", ctx, &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostTrustDomainJSONRequestBody{
					Name: "prod.example.org",
					X509: &swaclient.X509ConfigurationInput{WorkloadTtl: &workloadTTL},
				}).Return(&swaclient.PostTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: td,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful creation with certificate and CA config",
			data: TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustObject(ctx, x509AttrTypes, fullX509Model()),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse()
				m.On("PostTrustDomainWithResponse", ctx, &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostTrustDomainJSONRequestBody{
					Name: "prod.example.org",
					X509: &swaclient.X509ConfigurationInput{
						WorkloadTtl:                new(int32(3600)),
						IntermediateCertificateTtl: new(int32(172800)),
						IntermediateKeyAlgorithm:   new(swaclient.CAKeyAlgorithmECP384),
						Ca:                         fullX509CAInput(),
					},
				}).Return(&swaclient.PostTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: td,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "unknown computed x509 attributes are omitted so the server applies defaults",
			data: TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustObject(ctx, x509AttrTypes, X509ConfigModel{
					WorkloadTTL:                types.Int64Value(3600),
					IntermediateCertificateTTL: types.Int64Unknown(),
					IntermediateKeyAlgorithm:   types.StringUnknown(),
					CA: mustObject(ctx, x509CAAttrTypes, X509CAModel{
						Type:   types.StringValue("builtin"),
						Config: types.ObjectUnknown(x509CAConfigAttrTypes),
					}),
				}),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse()
				m.On("PostTrustDomainWithResponse", ctx, &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostTrustDomainJSONRequestBody{
					Name: "prod.example.org",
					X509: &swaclient.X509ConfigurationInput{
						WorkloadTtl: new(int32(3600)),
						Ca:          &swaclient.X509CAConfigurationInput{Type: swaclient.CATypeBuiltin},
					},
				}).Return(&swaclient.PostTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: td,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful creation with both JWT and X509 config",
			data: TrustDomainResourceModel{
				Name: types.StringValue("dev.example.org"),
				JWT:  mustJWTObject(ctx, "RS512", "RSA_4096", 86400, 300),
				X509: mustX509Object(ctx, 3600),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse()
				td.Name = "dev.example.org"
				workloadTTL := int32(3600)
				m.On("PostTrustDomainWithResponse", ctx, &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostTrustDomainJSONRequestBody{
					Name: "dev.example.org",
					Jwt: &swaclient.JWTConfigurationInput{
						SignatureAlgorithm: new(swaclient.JWTConfigurationInputSignatureAlgorithm("RS512")),
						SigningKeyType:     new(swaclient.JWTConfigurationInputSigningKeyType("RSA_4096")),
						SigningKeyTtl:      new(int32(86400)),
						TokenTtl:           new(int32(300)),
					},
					X509: &swaclient.X509ConfigurationInput{WorkloadTtl: &workloadTTL},
				}).Return(&swaclient.PostTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
					ApplicationxSecretsmgrV2JSON201: td,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during creation",
			data: TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostTrustDomainWithResponse", ctx, &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostTrustDomainJSONRequestBody{Name: "prod.example.org"}).
					Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error creating trust domain",
		},
		{
			name: "non-201 status code",
			data: TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostTrustDomainWithResponse", ctx, &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostTrustDomainJSONRequestBody{Name: "prod.example.org"}).
					Return(&swaclient.PostTrustDomainResponse{
						HTTPResponse: makeHTTPResponse(http.StatusConflict),
						Body:         []byte(`{"message":"already exists"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error creating trust domain",
		},
		{
			name: "nil response body",
			data: TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostTrustDomainWithResponse", ctx, &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostTrustDomainJSONRequestBody{Name: "prod.example.org"}).
					Return(&swaclient.PostTrustDomainResponse{
						HTTPResponse: makeHTTPResponse(http.StatusCreated),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error creating trust domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &TrustDomainResource{client: mockClient}

			req := resource.CreateRequest{
				Plan: newPlanWithSchema(getTrustDomainSchema()),
			}
			resp := &resource.CreateResponse{
				State: newStateWithSchema(getTrustDomainSchema()),
			}

			if diags := req.Plan.Set(ctx, &tt.data); diags.HasError() {
				t.Fatalf("failed to set plan: %v", diags)
			}
			r.Create(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					assertDiagContains(t, resp.Diagnostics, tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
			}
		})
	}
}

func TestTrustDomainResource_Read(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		data          TrustDomainResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		shouldRemove  bool
		errorContains string
	}{
		{
			name: "successful read",
			data: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse()
				m.On("GetTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.GetTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetTrustDomainResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: td,
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "read populates JWT config values from response",
			data: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				// Initial (stale) values — should be overwritten by API response.
				JWT:  mustJWTObject(ctx, "RS256", "RSA_2048", 1, 1),
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse() // RS512, RSA_4096, 86400, 300
				m.On("GetTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.GetTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetTrustDomainResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: td,
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "read populates X509 config values from response",
			data: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustX509Object(ctx, 1), // stale — should be overwritten
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse() // WorkloadTtl: 3600
				m.On("GetTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.GetTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetTrustDomainResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: td,
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "not found removes from state",
			data: TrustDomainResourceModel{
				Name: types.StringValue("missing.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetTrustDomainWithResponse", ctx, "missing.example.org", &swaclient.GetTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetTrustDomainResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNotFound),
					}, nil)
			},
			expectedError: false,
			shouldRemove:  true,
		},
		{
			name: "API error during read",
			data: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.GetTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(nil, fmt.Errorf("network error"))
			},
			expectedError: true,
			errorContains: "Error reading trust domain",
		},
		{
			name: "non-200 status code",
			data: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.GetTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetTrustDomainResponse{
						HTTPResponse: makeHTTPResponse(http.StatusInternalServerError),
						Body:         []byte(`{"message":"internal error"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error reading trust domain",
		},
		{
			name: "nil response body",
			data: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.GetTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetTrustDomainResponse{
						HTTPResponse: makeHTTPResponse(http.StatusOK),
					}, nil)
			},
			expectedError: true,
			errorContains: "No response body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &TrustDomainResource{client: mockClient}

			req := resource.ReadRequest{
				State: newStateWithSchema(getTrustDomainSchema()),
			}
			resp := &resource.ReadResponse{
				State: newStateWithSchema(getTrustDomainSchema()),
			}

			if diags := req.State.Set(ctx, &tt.data); diags.HasError() {
				t.Fatalf("failed to set state: %v", diags)
			}
			r.Read(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					assertDiagContains(t, resp.Diagnostics, tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
				if tt.shouldRemove {
					assert.True(t, resp.State.Raw.IsNull(), "expected resource to be removed from state")
				} else {
					var result TrustDomainResourceModel
					resp.State.Get(ctx, &result)
					assert.Equal(t, tt.data.Name.ValueString(), result.Name.ValueString())
					// If the test state had JWT/X509 config, verify values were refreshed.
					if !tt.data.JWT.IsNull() && !tt.data.JWT.IsUnknown() {
						require.False(t, result.JWT.IsNull())
						var jwtResult JWTConfigModel
						result.JWT.As(ctx, &jwtResult, basetypes.ObjectAsOptions{})
						assert.Equal(t, "RS512", jwtResult.SignatureAlgorithm.ValueString())
						assert.Equal(t, "RSA_4096", jwtResult.SigningKeyType.ValueString())
						assert.Equal(t, int64(86400), jwtResult.SigningKeyTTL.ValueInt64())
						assert.Equal(t, int64(300), jwtResult.TokenTTL.ValueInt64())
					}
					if !tt.data.X509.IsNull() && !tt.data.X509.IsUnknown() {
						require.False(t, result.X509.IsNull())
						var x509Result X509ConfigModel
						result.X509.As(ctx, &x509Result, basetypes.ObjectAsOptions{})
						assert.Equal(t, int64(3600), x509Result.WorkloadTTL.ValueInt64())
					}
				}
			}
		})
	}
}

func TestTrustDomainResource_Update(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		plan          TrustDomainResourceModel
		state         TrustDomainResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful update with JWT config",
			plan: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  mustJWTObject(ctx, "RS512", "RSA_4096", 86400, 600),
				X509: nullX509Object,
			},
			state: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse()
				sigAlg := swaclient.UpdateJWTConfigurationInputSignatureAlgorithm("RS512")
				keyType := swaclient.UpdateJWTConfigurationInputSigningKeyType("RSA_4096")
				signingKeyTTL := int32(86400)
				tokenTTL := int32(600)
				m.On("PatchTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchTrustDomainJSONRequestBody{
					Jwt: &swaclient.UpdateJWTConfigurationInput{
						SignatureAlgorithm: &sigAlg,
						SigningKeyType:     &keyType,
						SigningKeyTtl:      &signingKeyTTL,
						TokenTtl:           &tokenTTL,
					},
				}).Return(&swaclient.PatchTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: td,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful update with X509 config",
			plan: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustX509Object(ctx, 7200),
			},
			state: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse()
				m.On("PatchTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchTrustDomainJSONRequestBody{
					X509: &swaclient.UpdateX509ConfigurationInput{WorkloadTtl: new(int32(7200))},
				}).Return(&swaclient.PatchTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: td,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful update with certificate and CA config",
			plan: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustObject(ctx, x509AttrTypes, fullX509Model()),
			},
			state: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				td := makeTrustDomainResponse()
				m.On("PatchTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchTrustDomainJSONRequestBody{
					X509: &swaclient.UpdateX509ConfigurationInput{
						WorkloadTtl:                new(int32(3600)),
						IntermediateCertificateTtl: new(int32(172800)),
						IntermediateKeyAlgorithm:   new(swaclient.CAKeyAlgorithmECP384),
						Ca:                         fullX509CAInput(),
					},
				}).Return(&swaclient.PatchTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: td,
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "update sends only the x509 fields that changed",
			plan: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustObject(ctx, x509AttrTypes, func() X509ConfigModel {
					m := fullX509Model()
					m.WorkloadTTL = types.Int64Value(7200)
					return m
				}()),
			},
			state: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustObject(ctx, x509AttrTypes, fullX509Model()),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchTrustDomainJSONRequestBody{
					X509: &swaclient.UpdateX509ConfigurationInput{WorkloadTtl: new(int32(7200))},
				}).Return(&swaclient.PatchTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: makeTrustDomainResponse(),
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "update does not resend the carried-over intermediate TTL",
			plan: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustObject(ctx, x509AttrTypes, func() X509ConfigModel {
					m := fullX509Model()
					m.WorkloadTTL = types.Int64Value(7200)
					return m
				}()),
			},
			state: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustObject(ctx, x509AttrTypes, fullX509Model()),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchTrustDomainJSONRequestBody{
					X509: &swaclient.UpdateX509ConfigurationInput{WorkloadTtl: new(int32(7200))},
				}).Return(&swaclient.PatchTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: makeTrustDomainResponse(),
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "update sends only the changed CA config field with its type",
			plan: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustObject(ctx, x509AttrTypes, func() X509ConfigModel {
					m := fullX509Model()
					cfg, _ := types.ObjectValueFrom(ctx, x509CAConfigAttrTypes, &X509CAConfigModel{
						RootCATTL:                   types.Int64Value(31104000),
						RootKeyAlgorithm:            types.StringValue("RSA_4096"),
						RootRotationTriggerFraction: types.Float64Value(0.8),
					})
					m.CA = mustObject(ctx, x509CAAttrTypes, X509CAModel{Type: types.StringValue("builtin"), Config: cfg})
					return m
				}()),
			},
			state: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustObject(ctx, x509AttrTypes, fullX509Model()),
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchTrustDomainJSONRequestBody{
					X509: &swaclient.UpdateX509ConfigurationInput{
						Ca: &swaclient.X509CAConfigurationInput{
							Type:   swaclient.CATypeBuiltin,
							Config: &swaclient.BuiltinRootCAConfigurationInput{RootCaTtl: new(int32(31104000))},
						},
					},
				}).Return(&swaclient.PatchTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: makeTrustDomainResponse(),
				}, nil)
			},
			expectedError: false,
		},
		{
			name: "update requires jwt or x509",
			plan: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			state: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Invalid trust domain update",
		},
		{
			name: "API error during update",
			plan: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  mustJWTObject(ctx, "RS512", "RSA_4096", 86400, 300),
				X509: nullX509Object,
			},
			state: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sigAlg := swaclient.UpdateJWTConfigurationInputSignatureAlgorithm("RS512")
				keyType := swaclient.UpdateJWTConfigurationInputSigningKeyType("RSA_4096")
				signingKeyTTL := int32(86400)
				tokenTTL := int32(300)
				m.On("PatchTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchTrustDomainJSONRequestBody{
					Jwt: &swaclient.UpdateJWTConfigurationInput{
						SignatureAlgorithm: &sigAlg,
						SigningKeyType:     &keyType,
						SigningKeyTtl:      &signingKeyTTL,
						TokenTtl:           &tokenTTL,
					},
				}).Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error updating trust domain",
		},
		{
			name: "non-200 status code",
			plan: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  mustJWTObject(ctx, "RS512", "RSA_4096", 86400, 300),
				X509: nullX509Object,
			},
			state: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sigAlg := swaclient.UpdateJWTConfigurationInputSignatureAlgorithm("RS512")
				keyType := swaclient.UpdateJWTConfigurationInputSigningKeyType("RSA_4096")
				signingKeyTTL := int32(86400)
				tokenTTL := int32(300)
				m.On("PatchTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchTrustDomainJSONRequestBody{
					Jwt: &swaclient.UpdateJWTConfigurationInput{
						SignatureAlgorithm: &sigAlg,
						SigningKeyType:     &keyType,
						SigningKeyTtl:      &signingKeyTTL,
						TokenTtl:           &tokenTTL,
					},
				}).Return(&swaclient.PatchTrustDomainResponse{
					HTTPResponse: makeHTTPResponse(http.StatusBadRequest),
					Body:         []byte(`{"message":"invalid input"}`),
				}, nil)
			},
			expectedError: true,
			errorContains: "Error updating trust domain",
		},
		{
			name: "nil response body",
			plan: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  mustJWTObject(ctx, "RS512", "RSA_4096", 86400, 300),
				X509: nullX509Object,
			},
			state: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				sigAlg := swaclient.UpdateJWTConfigurationInputSignatureAlgorithm("RS512")
				keyType := swaclient.UpdateJWTConfigurationInputSigningKeyType("RSA_4096")
				signingKeyTTL := int32(86400)
				tokenTTL := int32(300)
				m.On("PatchTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.PatchTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PatchTrustDomainJSONRequestBody{
					Jwt: &swaclient.UpdateJWTConfigurationInput{
						SignatureAlgorithm: &sigAlg,
						SigningKeyType:     &keyType,
						SigningKeyTtl:      &signingKeyTTL,
						TokenTtl:           &tokenTTL,
					},
				}).Return(&swaclient.PatchTrustDomainResponse{
					HTTPResponse: makeHTTPResponse(http.StatusOK),
				}, nil)
			},
			expectedError: true,
			errorContains: "No response body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &TrustDomainResource{client: mockClient}

			req := resource.UpdateRequest{
				Plan:  newPlanWithSchema(getTrustDomainSchema()),
				State: newStateWithSchema(getTrustDomainSchema()),
			}
			resp := &resource.UpdateResponse{
				State: newStateWithSchema(getTrustDomainSchema()),
			}

			if diags := req.Plan.Set(ctx, &tt.plan); diags.HasError() {
				t.Fatalf("failed to set plan: %v", diags)
			}
			if diags := req.State.Set(ctx, &tt.state); diags.HasError() {
				t.Fatalf("failed to set state: %v", diags)
			}
			r.Update(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					assertDiagContains(t, resp.Diagnostics, tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
			}
		})
	}
}

func TestTrustDomainResource_Delete(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		data          TrustDomainResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful deletion",
			data: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.DeleteTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteTrustDomainResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNoContent),
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "deletion of already deleted resource (404)",
			data: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.DeleteTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteTrustDomainResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNotFound),
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during deletion",
			data: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.DeleteTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error deleting trust domain",
		},
		{
			name: "non-success status code",
			data: TrustDomainResourceModel{
				ID:   types.StringValue("prod.example.org"),
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteTrustDomainWithResponse", ctx, "prod.example.org", &swaclient.DeleteTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteTrustDomainResponse{
						HTTPResponse: makeHTTPResponse(http.StatusInternalServerError),
						Body:         []byte(`{"message":"internal error"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error deleting trust domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &TrustDomainResource{client: mockClient}

			req := resource.DeleteRequest{
				State: newStateWithSchema(getTrustDomainSchema()),
			}
			resp := &resource.DeleteResponse{
				State: newStateWithSchema(getTrustDomainSchema()),
			}

			if diags := req.State.Set(ctx, &tt.data); diags.HasError() {
				t.Fatalf("failed to set state: %v", diags)
			}
			r.Delete(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					assertDiagContains(t, resp.Diagnostics, tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
			}
		})
	}
}

func TestTrustDomainResource_NilClientWarning(t *testing.T) {
	ctx := context.Background()
	r := &TrustDomainResource{}

	createReq := resource.CreateRequest{
		Plan: newPlanWithSchema(getTrustDomainSchema()),
	}
	createResp := &resource.CreateResponse{
		State: newStateWithSchema(getTrustDomainSchema()),
	}
	r.Create(ctx, createReq, createResp)
	assert.False(t, createResp.Diagnostics.HasError())
	assertWarningContains(t, createResp.Diagnostics, "Provider client not configured")

	readReq := resource.ReadRequest{
		State: newStateWithSchema(getTrustDomainSchema()),
	}
	readResp := &resource.ReadResponse{
		State: newStateWithSchema(getTrustDomainSchema()),
	}
	r.Read(ctx, readReq, readResp)
	assert.False(t, readResp.Diagnostics.HasError())
	assertWarningContains(t, readResp.Diagnostics, "Provider client not configured")

	updateReq := resource.UpdateRequest{
		Plan:  newPlanWithSchema(getTrustDomainSchema()),
		State: newStateWithSchema(getTrustDomainSchema()),
	}
	updateResp := &resource.UpdateResponse{
		State: newStateWithSchema(getTrustDomainSchema()),
	}
	r.Update(ctx, updateReq, updateResp)
	assert.False(t, updateResp.Diagnostics.HasError())
	assertWarningContains(t, updateResp.Diagnostics, "Provider client not configured")

	deleteReq := resource.DeleteRequest{
		State: newStateWithSchema(getTrustDomainSchema()),
	}
	deleteResp := &resource.DeleteResponse{
		State: newStateWithSchema(getTrustDomainSchema()),
	}
	r.Delete(ctx, deleteReq, deleteResp)
	assert.False(t, deleteResp.Diagnostics.HasError())
	assertWarningContains(t, deleteResp.Diagnostics, "Provider client not configured")
}

// --- Schema plan modifier tests ---

func TestTrustDomainResource_Schema_RequiresReplace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &TrustDomainResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	tests := []struct {
		attrPath      string
		shouldReplace bool
	}{
		{"name", true},
		{"id", false},
		{"jwt", false},
		{"x509", false},
	}

	const requiresReplaceDesc = "If the value of this attribute changes, Terraform will destroy and recreate the resource."

	for _, tc := range tests {
		t.Run(tc.attrPath, func(t *testing.T) {
			t.Parallel()
			attr := schemaResp.Schema.Attributes[tc.attrPath]
			assert.NotNil(t, attr, "attribute %q not found in schema", tc.attrPath)

			hasRequiresReplace := false
			switch a := attr.(type) {
			case schema.StringAttribute:
				for _, pm := range a.PlanModifiers {
					if pm.Description(ctx) == requiresReplaceDesc {
						hasRequiresReplace = true
					}
				}
			case schema.SingleNestedAttribute:
				for _, pm := range a.PlanModifiers {
					if pm.Description(ctx) == requiresReplaceDesc {
						hasRequiresReplace = true
					}
				}
			}

			if tc.shouldReplace {
				assert.True(t, hasRequiresReplace, "attribute %q should have RequiresReplace", tc.attrPath)
			} else {
				assert.False(t, hasRequiresReplace, "attribute %q should NOT have RequiresReplace", tc.attrPath)
			}
		})
	}
}

// --- Lifecycle tests (mock-client acceptance style) ---

func TestTrustDomainResource_CreateAndDelete(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)
	now := time.Now()

	tdResp := &swaclient.TrustDomainResponse{
		Name: "test-td", CreatedAt: now, UpdatedAt: now,
		Jwt:  swaclient.JWTConfiguration{SignatureAlgorithm: "RS512", SigningKeyType: "RSA_4096", SigningKeyTtl: 86400, TokenTtl: 300},
		X509: swaclient.X509Configuration{WorkloadTtl: 3600},
	}

	mockClient.EXPECT().
		PostTrustDomainWithResponse(mock.Anything, mock.Anything, mock.Anything).
		Return(&swaclient.PostTrustDomainResponse{
			HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: tdResp,
		}, nil).Times(1)

	mockClient.EXPECT().
		GetTrustDomainWithResponse(mock.Anything, "test-td", mock.Anything).
		Return(&swaclient.GetTrustDomainResponse{
			HTTPResponse:                    makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: tdResp,
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteTrustDomainWithResponse(mock.Anything, "test-td", mock.Anything).
		Return(&swaclient.DeleteTrustDomainResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_trust_domain" "test" {
  name = "test-td"
  jwt  = {}
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttr("conjur_swa_trust_domain.test", "name", "test-td"),
					tfresource.TestCheckResourceAttr("conjur_swa_trust_domain.test", "id", "test-td"),
				),
			},
		},
	})
}

func TestTrustDomainResource_NameChange_RequiresReplace(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)
	now := time.Now()

	mockClient.EXPECT().
		PostTrustDomainWithResponse(mock.Anything, mock.Anything,
			mock.MatchedBy(func(body swaclient.PostTrustDomainJSONRequestBody) bool { return body.Name == "td-one" })).
		Return(&swaclient.PostTrustDomainResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.TrustDomainResponse{
				Name: "td-one", CreatedAt: now, UpdatedAt: now,
				Jwt:  swaclient.JWTConfiguration{SignatureAlgorithm: "RS512", SigningKeyType: "RSA_4096", SigningKeyTtl: 86400, TokenTtl: 300},
				X509: swaclient.X509Configuration{WorkloadTtl: 3600},
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		PostTrustDomainWithResponse(mock.Anything, mock.Anything,
			mock.MatchedBy(func(body swaclient.PostTrustDomainJSONRequestBody) bool { return body.Name == "td-two" })).
		Return(&swaclient.PostTrustDomainResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.TrustDomainResponse{
				Name: "td-two", CreatedAt: now, UpdatedAt: now,
				Jwt:  swaclient.JWTConfiguration{SignatureAlgorithm: "RS512", SigningKeyType: "RSA_4096", SigningKeyTtl: 86400, TokenTtl: 300},
				X509: swaclient.X509Configuration{WorkloadTtl: 3600},
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetTrustDomainWithResponse(mock.Anything, "td-one", mock.Anything).
		Return(&swaclient.GetTrustDomainResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.TrustDomainResponse{
				Name: "td-one", CreatedAt: now, UpdatedAt: now,
				Jwt:  swaclient.JWTConfiguration{SignatureAlgorithm: "RS512", SigningKeyType: "RSA_4096", SigningKeyTtl: 86400, TokenTtl: 300},
				X509: swaclient.X509Configuration{WorkloadTtl: 3600},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		GetTrustDomainWithResponse(mock.Anything, "td-two", mock.Anything).
		Return(&swaclient.GetTrustDomainResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.TrustDomainResponse{
				Name: "td-two", CreatedAt: now, UpdatedAt: now,
				Jwt:  swaclient.JWTConfiguration{SignatureAlgorithm: "RS512", SigningKeyType: "RSA_4096", SigningKeyTtl: 86400, TokenTtl: 300},
				X509: swaclient.X509Configuration{WorkloadTtl: 3600},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteTrustDomainWithResponse(mock.Anything, "td-one", mock.Anything).
		Return(&swaclient.DeleteTrustDomainResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	mockClient.EXPECT().
		DeleteTrustDomainWithResponse(mock.Anything, "td-two", mock.Anything).
		Return(&swaclient.DeleteTrustDomainResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_trust_domain" "test" {
  name = "td-one"
  jwt  = {}
}
`,
				Check: tfresource.TestCheckResourceAttr("conjur_swa_trust_domain.test", "name", "td-one"),
			},
			{
				Config: `
resource "conjur_swa_trust_domain" "test" {
  name = "td-two"
  jwt  = {}
}
`,
				Check: tfresource.TestCheckResourceAttr("conjur_swa_trust_domain.test", "name", "td-two"),
			},
		},
	})
}

func TestTrustDomainResource_JWTUpdate_InPlace(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)
	now := time.Now()

	mockClient.EXPECT().
		PostTrustDomainWithResponse(mock.Anything, mock.Anything, mock.Anything).
		Return(&swaclient.PostTrustDomainResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.TrustDomainResponse{
				Name: "test-td", CreatedAt: now, UpdatedAt: now,
				Jwt:  swaclient.JWTConfiguration{SignatureAlgorithm: "RS512", SigningKeyType: "RSA_4096", SigningKeyTtl: 86400, TokenTtl: 300},
				X509: swaclient.X509Configuration{WorkloadTtl: 3600},
			},
		}, nil).Times(1)

	// Two reads: post-apply step-1 refresh + pre-plan step-2 refresh.
	mockClient.EXPECT().
		GetTrustDomainWithResponse(mock.Anything, "test-td", mock.Anything).
		Return(&swaclient.GetTrustDomainResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.TrustDomainResponse{
				Name: "test-td", CreatedAt: now, UpdatedAt: now,
				Jwt:  swaclient.JWTConfiguration{SignatureAlgorithm: "RS512", SigningKeyType: "RSA_4096", SigningKeyTtl: 86400, TokenTtl: 300},
				X509: swaclient.X509Configuration{WorkloadTtl: 3600},
			},
		}, nil).Times(2)

	mockClient.EXPECT().
		PatchTrustDomainWithResponse(mock.Anything, "test-td", mock.Anything, mock.Anything).
		Return(&swaclient.PatchTrustDomainResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.TrustDomainResponse{
				Name: "test-td", CreatedAt: now, UpdatedAt: now,
				Jwt:  swaclient.JWTConfiguration{SignatureAlgorithm: "ES256", SigningKeyType: "EC_P256", SigningKeyTtl: 86400, TokenTtl: 600},
				X509: swaclient.X509Configuration{WorkloadTtl: 3600},
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetTrustDomainWithResponse(mock.Anything, "test-td", mock.Anything).
		Return(&swaclient.GetTrustDomainResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.TrustDomainResponse{
				Name: "test-td", CreatedAt: now, UpdatedAt: now,
				Jwt:  swaclient.JWTConfiguration{SignatureAlgorithm: "ES256", SigningKeyType: "EC_P256", SigningKeyTtl: 86400, TokenTtl: 600},
				X509: swaclient.X509Configuration{WorkloadTtl: 3600},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteTrustDomainWithResponse(mock.Anything, "test-td", mock.Anything).
		Return(&swaclient.DeleteTrustDomainResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_trust_domain" "test" {
  name = "test-td"
  jwt  = {}
}
`,
				Check: tfresource.TestCheckResourceAttr("conjur_swa_trust_domain.test", "name", "test-td"),
			},
			{
				Config: `
resource "conjur_swa_trust_domain" "test" {
  name = "test-td"
  jwt = {
    signature_algorithm = "ES256"
    signing_key_type    = "EC_P256"
    token_ttl           = 600
  }
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttr("conjur_swa_trust_domain.test", "jwt.signature_algorithm", "ES256"),
					tfresource.TestCheckResourceAttr("conjur_swa_trust_domain.test", "jwt.token_ttl", "600"),
				),
			},
		},
	})
}

func TestTrustDomainResource_ModifyPlan(t *testing.T) {
	ctx := context.Background()
	s := getTrustDomainSchema()

	plan := func(workloadTTL int64, intermediate types.Int64) tfsdk.Plan {
		m := fullX509Model()
		m.WorkloadTTL = types.Int64Value(workloadTTL)
		m.IntermediateCertificateTTL = intermediate
		return planFromModel(t, s, TrustDomainResourceModel{
			Name: types.StringValue("prod.example.org"),
			JWT:  nullJWTObject,
			X509: mustObject(ctx, x509AttrTypes, &m),
		})
	}
	// config only matters for whether the user wrote intermediate_certificate_ttl.
	config := func(intermediate types.Int64) tfsdk.Config {
		m := fullX509Model()
		m.IntermediateCertificateTTL = intermediate
		return tfsdk.Config{Schema: s, Raw: planFromModel(t, s, TrustDomainResourceModel{
			Name: types.StringValue("prod.example.org"),
			JWT:  nullJWTObject,
			X509: mustObject(ctx, x509AttrTypes, &m),
		}).Raw}
	}

	tests := []struct {
		name          string
		plan          tfsdk.Plan
		config        tfsdk.Config
		errorContains []string
	}{
		{
			name:   "carried-over intermediate that still fits",
			plan:   plan(7200, types.Int64Value(86400)),
			config: config(types.Int64Null()),
		},
		{
			name:   "intermediate exactly twice the workload",
			plan:   plan(43200, types.Int64Value(86400)),
			config: config(types.Int64Null()),
		},
		{
			name:   "intermediate not yet known (create)",
			plan:   plan(50000, types.Int64Unknown()),
			config: config(types.Int64Null()),
		},
		{
			name:   "configured intermediate that fits",
			plan:   plan(50000, types.Int64Value(100000)),
			config: config(types.Int64Value(100000)),
		},
		{
			name:   "carried-over intermediate that the raised workload outgrows",
			plan:   plan(50000, types.Int64Value(86400)),
			config: config(types.Int64Null()),
			errorContains: []string{
				"86400 is less than 2 x 50000",
				"kept when it is not configured",
				"at least 100000",
			},
		},
		{
			name:          "configured intermediate that is too short",
			plan:          plan(50000, types.Int64Value(86400)),
			config:        config(types.Int64Value(86400)),
			errorContains: []string{"86400 is less than 2 x 50000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &resource.ModifyPlanResponse{Plan: tt.plan}
			(&TrustDomainResource{}).ModifyPlan(ctx, resource.ModifyPlanRequest{Plan: tt.plan, Config: tt.config}, resp)

			if len(tt.errorContains) == 0 {
				assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
				return
			}
			require.True(t, resp.Diagnostics.HasError())
			for _, want := range tt.errorContains {
				assert.Contains(t, resp.Diagnostics.Errors()[0].Detail(), want)
			}
		})
	}

	t.Run("configured intermediate does not get the keep-it hint", func(t *testing.T) {
		resp := &resource.ModifyPlanResponse{}
		(&TrustDomainResource{}).ModifyPlan(ctx, resource.ModifyPlanRequest{
			Plan: plan(50000, types.Int64Value(86400)), Config: config(types.Int64Value(86400)),
		}, resp)
		require.True(t, resp.Diagnostics.HasError())
		assert.NotContains(t, resp.Diagnostics.Errors()[0].Detail(), "kept when it is not configured")
	})

	t.Run("destroy plan is ignored", func(t *testing.T) {
		resp := &resource.ModifyPlanResponse{}
		null := tfsdk.Plan{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
		(&TrustDomainResource{}).ModifyPlan(ctx, resource.ModifyPlanRequest{Plan: null, Config: config(types.Int64Null())}, resp)
		assert.False(t, resp.Diagnostics.HasError())
	})
}

func TestCAKeyAlgorithmPtr(t *testing.T) {
	assert.Nil(t, caKeyAlgorithmPtr(types.StringNull()))
	assert.Nil(t, caKeyAlgorithmPtr(types.StringUnknown()))

	got := caKeyAlgorithmPtr(types.StringValue("EC_P384"))
	require.NotNil(t, got)
	assert.Equal(t, swaclient.CAKeyAlgorithmECP384, *got)
}

func TestX509InputFromModel(t *testing.T) {
	ctx := context.Background()

	t.Run("full model maps every field", func(t *testing.T) {
		m := fullX509Model()
		got, diags := x509InputFromModel(ctx, &m)
		require.False(t, diags.HasError(), "%v", diags)

		assert.Equal(t, swaclient.UpdateX509ConfigurationInput{
			WorkloadTtl:                new(int32(3600)),
			IntermediateCertificateTtl: new(int32(172800)),
			IntermediateKeyAlgorithm:   new(swaclient.CAKeyAlgorithmECP384),
			Ca:                         fullX509CAInput(),
		}, got)
	})

	t.Run("null and unknown values are omitted", func(t *testing.T) {
		m := X509ConfigModel{
			WorkloadTTL:                types.Int64Value(3600),
			IntermediateCertificateTTL: types.Int64Unknown(),
			IntermediateKeyAlgorithm:   types.StringUnknown(),
			CA:                         types.ObjectNull(x509CAAttrTypes),
		}
		got, diags := x509InputFromModel(ctx, &m)
		require.False(t, diags.HasError(), "%v", diags)

		assert.Equal(t, swaclient.UpdateX509ConfigurationInput{WorkloadTtl: new(int32(3600))}, got)
	})

	t.Run("ca with unset config sends type only", func(t *testing.T) {
		m := X509ConfigModel{
			WorkloadTTL:                types.Int64Value(3600),
			IntermediateCertificateTTL: types.Int64Null(),
			IntermediateKeyAlgorithm:   types.StringNull(),
			CA: mustObject(ctx, x509CAAttrTypes, X509CAModel{
				Type:   types.StringValue("builtin"),
				Config: types.ObjectNull(x509CAConfigAttrTypes),
			}),
		}
		got, diags := x509InputFromModel(ctx, &m)
		require.False(t, diags.HasError(), "%v", diags)

		require.NotNil(t, got.Ca)
		assert.Equal(t, swaclient.CATypeBuiltin, got.Ca.Type)
		assert.Nil(t, got.Ca.Config)
	})

	t.Run("ca config with unknown attributes omits them", func(t *testing.T) {
		cfg := mustObject(ctx, x509CAConfigAttrTypes, X509CAConfigModel{
			RootCATTL:                   types.Int64Value(20736000),
			RootKeyAlgorithm:            types.StringUnknown(),
			RootRotationTriggerFraction: types.Float64Unknown(),
		})
		m := X509ConfigModel{
			WorkloadTTL:                types.Int64Value(3600),
			IntermediateCertificateTTL: types.Int64Null(),
			IntermediateKeyAlgorithm:   types.StringNull(),
			CA:                         mustObject(ctx, x509CAAttrTypes, X509CAModel{Type: types.StringValue("builtin"), Config: cfg}),
		}
		got, diags := x509InputFromModel(ctx, &m)
		require.False(t, diags.HasError(), "%v", diags)

		require.NotNil(t, got.Ca)
		assert.Equal(t, &swaclient.BuiltinRootCAConfigurationInput{RootCaTtl: new(int32(20736000))}, got.Ca.Config)
	})
}

func TestChangedX509Input(t *testing.T) {
	ctx := context.Background()
	m := fullX509Model()
	full, diags := x509InputFromModel(ctx, &m)
	require.False(t, diags.HasError(), "%v", diags)

	t.Run("identical plan and state sends nothing", func(t *testing.T) {
		assert.Equal(t, swaclient.UpdateX509ConfigurationInput{}, changedX509Input(full, full))
	})

	t.Run("only changed top-level fields are sent", func(t *testing.T) {
		plan := full
		plan.WorkloadTtl = new(int32(7200))

		got := changedX509Input(plan, full)

		assert.Equal(t, swaclient.UpdateX509ConfigurationInput{WorkloadTtl: new(int32(7200))}, got)
	})

	t.Run("changed ca config field is sent with type and without unchanged siblings", func(t *testing.T) {
		plan := full
		plan.Ca = &swaclient.X509CAConfigurationInput{
			Type: swaclient.CATypeBuiltin,
			Config: &swaclient.BuiltinRootCAConfigurationInput{
				RootCaTtl:                   new(int32(31104000)),
				RootKeyAlgorithm:            full.Ca.Config.RootKeyAlgorithm,
				RootRotationTriggerFraction: full.Ca.Config.RootRotationTriggerFraction,
			},
		}

		got := changedX509Input(plan, full)

		assert.Equal(t, swaclient.UpdateX509ConfigurationInput{
			Ca: &swaclient.X509CAConfigurationInput{
				Type:   swaclient.CATypeBuiltin,
				Config: &swaclient.BuiltinRootCAConfigurationInput{RootCaTtl: new(int32(31104000))},
			},
		}, got)
	})

	t.Run("unchanged ca is dropped entirely", func(t *testing.T) {
		got := changedX509Input(swaclient.UpdateX509ConfigurationInput{Ca: fullX509CAInput()}, full)
		assert.Nil(t, got.Ca)
	})

	t.Run("ca added where state has none sends everything", func(t *testing.T) {
		got := changedX509Input(
			swaclient.UpdateX509ConfigurationInput{Ca: fullX509CAInput()},
			swaclient.UpdateX509ConfigurationInput{},
		)
		assert.Equal(t, fullX509CAInput(), got.Ca)
	})

	t.Run("omitted plan fields are never sent", func(t *testing.T) {
		got := changedX509Input(swaclient.UpdateX509ConfigurationInput{}, full)
		assert.Equal(t, swaclient.UpdateX509ConfigurationInput{}, got)
	})
}
