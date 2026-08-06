package provider

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
	swamocks "github.com/cyberark/terraform-provider-conjur/internal/swa/client/mocks"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
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

// mustX509Object builds a types.Object for X509 config in tests, panicking on error.
func mustX509Object(ctx context.Context, workloadTTL int64) types.Object {
	obj, diags := types.ObjectValueFrom(ctx, x509AttrTypes, &X509ConfigModel{
		WorkloadTTL: types.Int64Value(workloadTTL),
	})
	if diags.HasError() {
		panic(fmt.Sprintf("mustX509Object: %v", diags))
	}
	return obj
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
				sigAlg := swaclient.JWTConfigurationInputSignatureAlgorithm("RS512")
				keyType := swaclient.JWTConfigurationInputSigningKeyType("RSA_4096")
				signingKeyTTL := int32(86400)
				tokenTTL := int32(300)
				m.On("PostTrustDomainWithResponse", ctx, &swaclient.PostTrustDomainParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, swaclient.PostTrustDomainJSONRequestBody{
					Name: "dev.example.org",
					Jwt: &swaclient.JWTConfigurationInput{
						SignatureAlgorithm: &sigAlg,
						SigningKeyType:     &keyType,
						SigningKeyTtl:      &signingKeyTTL,
						TokenTtl:           &tokenTTL,
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
					X509: &swaclient.UpdateX509ConfigurationInput{WorkloadTtl: 7200},
				}).Return(&swaclient.PatchTrustDomainResponse{
					HTTPResponse:                    makeHTTPResponse(http.StatusOK),
					ApplicationxSecretsmgrV2JSON200: td,
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

func TestTrustDomainResource_ValidateConfig(t *testing.T) {
	tests := []struct {
		name          string
		data          TrustDomainResourceModel
		expectedError bool
		errorContains string
	}{
		{
			name: "valid with jwt",
			data: TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  mustJWTObject(context.Background(), "RS512", "RSA_4096", 86400, 300),
				X509: nullX509Object,
			},
			expectedError: false,
		},
		{
			name: "valid with x509",
			data: TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: mustX509Object(context.Background(), 3600),
			},
			expectedError: false,
		},
		{
			name: "valid without jwt or x509",
			data: TrustDomainResourceModel{
				Name: types.StringValue("prod.example.org"),
				JWT:  nullJWTObject,
				X509: nullX509Object,
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			r := &TrustDomainResource{}
			s := getTrustDomainSchema()
			plan := newPlanWithSchema(s)
			plan.Set(ctx, &tt.data)

			req := resource.ValidateConfigRequest{
				Config: buildTrustDomainConfigFromPlan(plan, s),
			}
			resp := &resource.ValidateConfigResponse{}
			r.ValidateConfig(ctx, req, resp)

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

func buildTrustDomainConfigFromPlan(plan tfsdk.Plan, s schema.Schema) tfsdk.Config {
	return tfsdk.Config{
		Raw:    plan.Raw,
		Schema: s,
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
