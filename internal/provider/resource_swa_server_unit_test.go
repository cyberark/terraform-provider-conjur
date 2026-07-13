package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
	swamocks "github.com/cyberark/terraform-provider-conjur/internal/swa/client/mocks"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func makeCreateServerResponse(name, authnID string) *swaclient.CreateServerResponse {
	return &swaclient.CreateServerResponse{
		Name:    name,
		AuthnId: authnID,
		Authentication: swaclient.CreateServerAuthentication{
			Type: "JWT",
		},
	}
}

func TestServerResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          ServerResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful creation with JWT auth",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("my-workload"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringValue("https://issuer.example.org/.well-known/jwks.json"),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				resp := makeCreateServerResponse("my-server", "dHJ1c3RfZG9tYWlu")
				m.On("PostServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(&swaclient.PostServerResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
						ApplicationxSecretsmgrV2JSON201: resp,
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "invalid server_group_id format",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("invalid-no-slash"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringValue("https://issuer.example.org/.well-known/jwks.json"),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Invalid server group ID",
		},
		{
			name: "unsupported auth type",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("API_KEY"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Invalid auth type",
		},
		{
			name: "API error during creation",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringValue("https://issuer.example.org/.well-known/jwks.json"),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error creating server",
		},
		{
			name: "non-201 status code",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringValue("https://issuer.example.org/.well-known/jwks.json"),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(&swaclient.PostServerResponse{
						HTTPResponse: makeHTTPResponse(http.StatusConflict),
						Body:         []byte(`{"message":"already exists"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error creating server",
		},
		{
			name: "successful creation with all optional JWT fields",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("my-workload"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringValue("https://api.example.org"),
					JWKSURI:    types.StringValue("https://issuer.example.org/.well-known/jwks.json"),
					CACert:     types.StringValue("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				resp := makeCreateServerResponse("my-server", "dHJ1c3RfZG9tYWlu")
				m.On("PostServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(&swaclient.PostServerResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
						ApplicationxSecretsmgrV2JSON201: resp,
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful creation with inline public keys",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("my-workload"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringValue(`{"type":"jwks","value":{"keys":[]}}`),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				resp := makeCreateServerResponse("my-server", "dHJ1c3RfZG9tYWlu")
				m.On("PostServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(&swaclient.PostServerResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
						ApplicationxSecretsmgrV2JSON201: resp,
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "successful creation with identity configuration",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("my-workload"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringValue("https://issuer.example.org/.well-known/jwks.json"),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
					Identity: func() *ServerAuthenticationIdentityModel {
						ctx := context.Background()
						aliases, _ := types.MapValueFrom(ctx, types.StringType, map[string]string{"sub": "subject"})
						claims, _ := types.ListValueFrom(ctx, types.StringType, []string{"sub", "iss"})
						return &ServerAuthenticationIdentityModel{
							ClaimAliases:     aliases,
							EnforcedClaims:   claims,
							IdentityPath:     types.StringValue("/data/my-workload"),
							TokenAppProperty: types.StringValue("sub"),
						}
					}(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				resp := makeCreateServerResponse("my-server", "dHJ1c3RfZG9tYWlu")
				m.On("PostServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(&swaclient.PostServerResponse{
						HTTPResponse:                    makeHTTPResponse(http.StatusCreated),
						ApplicationxSecretsmgrV2JSON201: resp,
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "nil response body on 201",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringValue("https://issuer.example.org/.well-known/jwks.json"),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PostServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(&swaclient.PostServerResponse{
						HTTPResponse: makeHTTPResponse(http.StatusCreated),
						// ApplicationxSecretsmgrV2JSON201 intentionally nil
					}, nil)
			},
			expectedError: true,
			errorContains: "Error creating server",
		},
		{
			name: "missing jwks_uri and public_keys",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Invalid auth configuration",
		},
		{
			name: "public_keys requires issuer",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringNull(),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringValue(`{"type":"jwks","value":{"keys":[]}}`),
				},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Invalid auth configuration",
		},
		{
			name: "identity_path requires token_app_property",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringValue("https://issuer.example.org/.well-known/jwks.json"),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
					Identity: &ServerAuthenticationIdentityModel{
						ClaimAliases:     types.MapNull(types.StringType),
						EnforcedClaims:   types.ListNull(types.StringType),
						IdentityPath:     types.StringValue("/data/workload"),
						TokenAppProperty: types.StringNull(),
					},
				},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Invalid auth.identity configuration",
		},
		{
			name: "invalid public_keys JSON",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringValue("not-valid-json"),
				},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Invalid public_keys JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &ServerResource{client: mockClient}

			req := resource.CreateRequest{
				Plan: newPlanWithSchema(getServerTestSchema()),
			}
			resp := &resource.CreateResponse{
				State: newStateWithSchema(getServerTestSchema()),
			}

			ctx := context.Background()
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

func TestServerResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          ServerResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful deletion",
			data: ServerResourceModel{
				ID:            types.StringValue("prod.example.org/prod-servers/my-server"),
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				AuthnID:       types.StringValue("dHJ1c3RfZG9tYWlu"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.ServerName("my-server"), &swaclient.DeleteServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteServerResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNoContent),
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "deletion of already deleted resource (404)",
			data: ServerResourceModel{
				ID:            types.StringValue("prod.example.org/prod-servers/my-server"),
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				AuthnID:       types.StringValue("dHJ1c3RfZG9tYWlu"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.ServerName("my-server"), &swaclient.DeleteServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteServerResponse{
						HTTPResponse: makeHTTPResponse(http.StatusNotFound),
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "invalid ID format",
			data: ServerResourceModel{
				ID:            types.StringValue("invalid"),
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				AuthnID:       types.StringValue("dHJ1c3RfZG9tYWlu"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Invalid server ID",
		},
		{
			name: "non-success status code during deletion",
			data: ServerResourceModel{
				ID:            types.StringValue("prod.example.org/prod-servers/my-server"),
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				AuthnID:       types.StringValue("dHJ1c3RfZG9tYWlu"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.ServerName("my-server"), &swaclient.DeleteServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.DeleteServerResponse{
						HTTPResponse: makeHTTPResponse(http.StatusInternalServerError),
						Body:         []byte(`{"message":"internal error"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error deleting server",
		},
		{
			name: "API error during deletion",
			data: ServerResourceModel{
				ID:            types.StringValue("prod.example.org/prod-servers/my-server"),
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				AuthnID:       types.StringValue("dHJ1c3RfZG9tYWlu"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("DeleteServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.ServerName("my-server"), &swaclient.DeleteServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error deleting server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &ServerResource{client: mockClient}

			req := resource.DeleteRequest{
				State: newStateWithSchema(getServerTestSchema()),
			}
			resp := &resource.DeleteResponse{
				State: newStateWithSchema(getServerTestSchema()),
			}

			ctx := context.Background()
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

func buildServerConfigFromPlan(plan tfsdk.Plan, s schema.Schema) tfsdk.Config {
	return tfsdk.Config{
		Raw:    plan.Raw,
		Schema: s,
	}
}

func getServerTestSchema() schema.Schema {
	r := &ServerResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}

func TestServerResource_Update(t *testing.T) {
	ctx := context.Background()
	r := &ServerResource{client: swamocks.NewMockClientWithResponsesInterface(t)}

	req := resource.UpdateRequest{
		Plan:  newPlanWithSchema(getServerTestSchema()),
		State: newStateWithSchema(getServerTestSchema()),
	}
	resp := &resource.UpdateResponse{
		State: newStateWithSchema(getServerTestSchema()),
	}

	r.Update(ctx, req, resp)
	assert.True(t, resp.Diagnostics.HasError())
	assertDiagContains(t, resp.Diagnostics, "Update Not Supported")
}

func TestServerResource_NilClientWarning(t *testing.T) {
	ctx := context.Background()
	r := &ServerResource{}
	s := getServerTestSchema()

	t.Run("create", func(t *testing.T) {
		req := resource.CreateRequest{Plan: newPlanWithSchema(s)}
		resp := &resource.CreateResponse{State: newStateWithSchema(s)}
		r.Create(ctx, req, resp)
		assert.False(t, resp.Diagnostics.HasError())
		assertWarningContains(t, resp.Diagnostics, "Provider client not configured")
	})

	t.Run("read", func(t *testing.T) {
		req := resource.ReadRequest{State: newStateWithSchema(s)}
		resp := &resource.ReadResponse{State: newStateWithSchema(s)}
		r.Read(ctx, req, resp)
		assert.False(t, resp.Diagnostics.HasError())
		assertWarningContains(t, resp.Diagnostics, "Provider client not configured")
	})

	t.Run("update", func(t *testing.T) {
		req := resource.UpdateRequest{Plan: newPlanWithSchema(s), State: newStateWithSchema(s)}
		resp := &resource.UpdateResponse{State: newStateWithSchema(s)}
		r.Update(ctx, req, resp)
		assert.False(t, resp.Diagnostics.HasError())
		assertWarningContains(t, resp.Diagnostics, "Provider client not configured")
	})

	t.Run("delete", func(t *testing.T) {
		req := resource.DeleteRequest{State: newStateWithSchema(s)}
		resp := &resource.DeleteResponse{State: newStateWithSchema(s)}
		r.Delete(ctx, req, resp)
		assert.False(t, resp.Diagnostics.HasError())
		assertWarningContains(t, resp.Diagnostics, "Provider client not configured")
	})
}

func TestServerResource_ValidateConfig(t *testing.T) {
	tests := []struct {
		name          string
		data          ServerResourceModel
		expectedError bool
		errorContains string
	}{
		{
			name: "valid config with jwks_uri",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringNull(),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringValue("https://issuer.example.org/.well-known/jwks.json"),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			expectedError: false,
		},
		{
			name: "missing jwks_uri and public_keys caught at plan time",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringNull(),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			expectedError: true,
			errorContains: "Invalid auth configuration",
		},
		{
			// public_keys sourced from a variable is unknown during ValidateConfig;
			// the presence check must not fire a false positive.
			name: "unknown public_keys does not trigger missing-key error",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringUnknown(),
				},
			},
			expectedError: false,
		},
		{
			// issuer sourced from a variable is unknown; the "issuer required when
			// public_keys is set" check must not fire a false positive.
			name: "unknown issuer does not trigger issuer-required error",
			data: ServerResourceModel{
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("sub"),
					Issuer:     types.StringUnknown(),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringValue(`{"keys":[]}`),
				},
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ServerResource{}
			s := getServerTestSchema()
			plan := newPlanWithSchema(s)
			plan.Set(context.Background(), &tt.data)

			req := resource.ValidateConfigRequest{
				Config: buildServerConfigFromPlan(plan, s),
			}
			resp := &resource.ValidateConfigResponse{}

			r.ValidateConfig(context.Background(), req, resp)

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

func TestServerResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          ServerResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		shouldRemove  bool
		errorContains string
	}{
		{
			name: "successful read refreshes state from API",
			data: ServerResourceModel{
				ID:            types.StringValue("prod.example.org/prod-servers/my-server"),
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				AuthnID:       types.StringValue("stale-authn-id"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("stale-sub"),
					Issuer:     types.StringValue("https://stale.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringNull(),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				authnID := "fresh-authn-id"
				m.On("GetServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.ServerName("my-server"), &swaclient.GetServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetServerResponse{
						HTTPResponse: makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: &swaclient.ServerResponse{
							Name:            "my-server",
							ServerGroupName: new("prod-servers"),
							AuthnId:         &authnID,
							Authentication: &swaclient.ServerAuthentication{
								Type: "JWT",
								Data: map[string]interface{}{
									"sub":      "my-workload",
									"issuer":   "https://issuer.example.org",
									"audience": "https://api.example.org",
								},
							},
						},
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "not found removes resource from state",
			data: ServerResourceModel{
				ID:            types.StringValue("prod.example.org/prod-servers/missing-server"),
				Name:          types.StringValue("missing-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:    types.StringValue("JWT"),
					Subject: types.StringValue("sub"),
					Issuer:  types.StringValue("https://issuer.example.org"),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.ServerName("missing-server"), &swaclient.GetServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetServerResponse{HTTPResponse: makeHTTPResponse(http.StatusNotFound)}, nil)
			},
			expectedError: false,
			shouldRemove:  true,
		},
		{
			name: "invalid ID format",
			data: ServerResourceModel{
				ID:   types.StringValue("invalid"),
				Name: types.StringValue("my-server"),
				Auth: &ServerAuthenticationModel{
					Type:    types.StringValue("JWT"),
					Subject: types.StringValue("sub"),
					Issuer:  types.StringValue("https://issuer.example.org"),
				},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Invalid server ID",
		},
		{
			name: "API error during read",
			data: ServerResourceModel{
				ID:            types.StringValue("prod.example.org/prod-servers/my-server"),
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:    types.StringValue("JWT"),
					Subject: types.StringValue("sub"),
					Issuer:  types.StringValue("https://issuer.example.org"),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("GetServerWithResponse", context.Background(), swaclient.TrustDomainName("prod.example.org"), swaclient.ServerGroupName("prod-servers"), swaclient.ServerName("my-server"), &swaclient.GetServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(nil, fmt.Errorf("network error"))
			},
			expectedError: true,
			errorContains: "Error reading server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &ServerResource{client: mockClient}
			ctx := context.Background()

			req := resource.ReadRequest{
				State: newStateWithSchema(getServerTestSchema()),
			}
			resp := &resource.ReadResponse{
				State: newStateWithSchema(getServerTestSchema()),
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
					var result ServerResourceModel
					resp.State.Get(ctx, &result)
					assert.Equal(t, "prod.example.org/prod-servers/my-server", result.ID.ValueString())
					assert.Equal(t, "prod.example.org/prod-servers", result.ServerGroupID.ValueString())
					assert.Equal(t, "fresh-authn-id", result.AuthnID.ValueString())
					assert.NotNil(t, result.Auth)
					assert.Equal(t, "my-workload", result.Auth.Subject.ValueString())
					assert.Equal(t, "https://issuer.example.org", result.Auth.Issuer.ValueString())
				}
			}
		})
	}
}

func TestServerResource_ImportState(t *testing.T) {
	ctx := context.Background()
	r := &ServerResource{}
	s := getServerTestSchema()

	req := resource.ImportStateRequest{ID: "prod.example.org/prod-servers/my-server"}
	resp := &resource.ImportStateResponse{
		State: newStateWithSchema(s),
	}

	r.ImportState(ctx, req, resp)
	assert.False(t, resp.Diagnostics.HasError())

	var result ServerResourceModel
	resp.State.Get(ctx, &result)
	assert.Equal(t, "prod.example.org/prod-servers/my-server", result.ID.ValueString())
	assert.Equal(t, "my-server", result.Name.ValueString())
	assert.Equal(t, "prod.example.org/prod-servers", result.ServerGroupID.ValueString())
}

func TestServerAuthFromCreateResponse_FullMapping(t *testing.T) {
	auth := swaclient.CreateServerAuthentication{Type: "JWT"}
	err := auth.Data.UnmarshalJSON([]byte(`{
		"sub":"workload-sub",
		"audience":"conjur",
		"jwks_uri":"https://issuer.example.org/.well-known/jwks.json",
		"issuer":"https://issuer.example.org",
		"ca_cert":"-----BEGIN CERTIFICATE-----...",
		"public_keys":{"type":"jwks","value":{"keys":[]}},
		"identity":{
			"claim_aliases":{"app":"app"},
			"enforced_claims":["sub","iss"],
			"identity_path":"/data/workload",
			"token_app_property":"sub"
		}
	}`))
	assert.NoError(t, err)

	result, err := serverAuthFromCreateResponse(auth)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	assert.Equal(t, swaclient.ServerAuthenticationType("jwt"), result.Type)
	assert.Equal(t, "workload-sub", result.Data["sub"])
	assert.Equal(t, "conjur", result.Data["audience"])
	assert.Equal(t, "https://issuer.example.org/.well-known/jwks.json", result.Data["jwks_uri"])
	assert.Equal(t, "https://issuer.example.org", result.Data["issuer"])
	assert.Equal(t, "-----BEGIN CERTIFICATE-----...", result.Data["ca_cert"])

	publicKeys, ok := result.Data["public_keys"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "jwks", publicKeys["type"])

	identityRaw, ok := result.Data["identity"]
	assert.True(t, ok)
	identity, ok := identityRaw.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, map[string]string{"app": "app"}, identity["claim_aliases"])
	assert.Equal(t, []string{"sub", "iss"}, identity["enforced_claims"])
	assert.Equal(t, "/data/workload", identity["identity_path"])
	assert.Equal(t, "sub", identity["token_app_property"])
}

func TestServerAuthFromCreateResponse_MissingAuthDataReturnsNil(t *testing.T) {
	result, err := serverAuthFromCreateResponse(swaclient.CreateServerAuthentication{Type: "JWT"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestServerAuthFromCreateResponse_EmptyIdentityOmitted(t *testing.T) {
	auth := swaclient.CreateServerAuthentication{Type: "JWT"}
	err := auth.Data.UnmarshalJSON([]byte(`{"sub":"workload-sub","identity":{}}`))
	assert.NoError(t, err)

	result, err := serverAuthFromCreateResponse(auth)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	_, hasIdentity := result.Data["identity"]
	assert.False(t, hasIdentity)
}

func TestSyncServerAuthFromResponse_FullMapping(t *testing.T) {
	ctx := context.Background()
	state := &ServerResourceModel{}

	auth := &swaclient.ServerAuthentication{
		Type: "jwt",
		Data: map[string]any{
			"sub":      "workload-sub",
			"audience": "conjur",
			"jwks_uri": "https://issuer.example.org/.well-known/jwks.json",
			"issuer":   "https://issuer.example.org",
			"ca_cert":  "-----BEGIN CERTIFICATE-----...",
			"public_keys": map[string]any{
				"type":  "jwks",
				"value": map[string]any{"keys": []any{}},
			},
			"identity": map[string]any{
				"claim_aliases":      map[string]any{"app": "app"},
				"enforced_claims":    []any{"sub", "iss"},
				"identity_path":      "/data/workload",
				"token_app_property": "sub",
			},
		},
	}

	err := syncServerAuthFromResponse(ctx, state, auth)
	assert.NoError(t, err)

	assert.NotNil(t, state.Auth)
	assert.Equal(t, "JWT", state.Auth.Type.ValueString())
	assert.Equal(t, "workload-sub", state.Auth.Subject.ValueString())
	assert.Equal(t, "conjur", state.Auth.Audience.ValueString())
	assert.Equal(t, "https://issuer.example.org/.well-known/jwks.json", state.Auth.JWKSURI.ValueString())
	assert.Equal(t, "https://issuer.example.org", state.Auth.Issuer.ValueString())
	assert.Equal(t, "-----BEGIN CERTIFICATE-----...", state.Auth.CACert.ValueString())

	var publicKeys map[string]any
	err = json.Unmarshal([]byte(state.Auth.PublicKeys.ValueString()), &publicKeys)
	assert.NoError(t, err)
	assert.Equal(t, "jwks", publicKeys["type"])

	assert.NotNil(t, state.Auth.Identity)
	var claimAliases map[string]string
	aliasDiags := state.Auth.Identity.ClaimAliases.ElementsAs(ctx, &claimAliases, false)
	assert.False(t, aliasDiags.HasError())
	assert.Equal(t, map[string]string{"app": "app"}, claimAliases)

	var enforcedClaims []string
	claimsDiags := state.Auth.Identity.EnforcedClaims.ElementsAs(ctx, &enforcedClaims, false)
	assert.False(t, claimsDiags.HasError())
	assert.Equal(t, []string{"sub", "iss"}, enforcedClaims)
	assert.Equal(t, "/data/workload", state.Auth.Identity.IdentityPath.ValueString())
	assert.Equal(t, "sub", state.Auth.Identity.TokenAppProperty.ValueString())
}

// TestSyncServerAuthFromResponse_PreservesPriorPublicKeysFormatting verifies that when the
// server echoes back semantically-equivalent but reformatted JSON (whitespace / key order),
// the prior config string is preserved byte-for-byte so Terraform does not report an
// inconsistent result after apply.
func TestSyncServerAuthFromResponse_PreservesPriorPublicKeysFormatting(t *testing.T) {
	ctx := context.Background()

	priorJSON := "{\n  \"type\": \"jwks\",\n  \"value\": {\"keys\": [{\"kid\": \"abc\"}]}\n}"
	state := &ServerResourceModel{
		Auth: &ServerAuthenticationModel{
			PublicKeys: types.StringValue(priorJSON),
		},
	}

	// Server returns the same content, differently formatted / key-ordered.
	auth := &swaclient.ServerAuthentication{
		Type: "jwt",
		Data: map[string]any{
			"sub": "workload-sub",
			"public_keys": map[string]any{
				"value": map[string]any{"keys": []any{map[string]any{"kid": "abc"}}},
				"type":  "jwks",
			},
		},
	}

	err := syncServerAuthFromResponse(ctx, state, auth)
	assert.NoError(t, err)
	assert.Equal(t, priorJSON, state.Auth.PublicKeys.ValueString(), "prior formatting must be preserved when semantically equal")
}

// TestSyncServerAuthFromResponse_UpdatesPublicKeysWhenChanged verifies that a genuinely
// different response value replaces the prior state value.
func TestSyncServerAuthFromResponse_UpdatesPublicKeysWhenChanged(t *testing.T) {
	ctx := context.Background()

	state := &ServerResourceModel{
		Auth: &ServerAuthenticationModel{
			PublicKeys: types.StringValue(`{"type":"jwks","value":{"keys":[{"kid":"old"}]}}`),
		},
	}

	auth := &swaclient.ServerAuthentication{
		Type: "jwt",
		Data: map[string]any{
			"sub": "workload-sub",
			"public_keys": map[string]any{
				"type":  "jwks",
				"value": map[string]any{"keys": []any{map[string]any{"kid": "new"}}},
			},
		},
	}

	err := syncServerAuthFromResponse(ctx, state, auth)
	assert.NoError(t, err)

	var publicKeys map[string]any
	err = json.Unmarshal([]byte(state.Auth.PublicKeys.ValueString()), &publicKeys)
	assert.NoError(t, err)
	value := publicKeys["value"].(map[string]any)
	keys := value["keys"].([]any)
	assert.Equal(t, "new", keys[0].(map[string]any)["kid"])
}

func TestSyncServerAuthFromResponse_MissingFieldsClearExistingValues(t *testing.T) {
	ctx := context.Background()
	state := &ServerResourceModel{
		Auth: &ServerAuthenticationModel{
			PublicKeys: types.StringValue(`{"type":"jwks","value":{"keys":[{"kid":"old"}]}}`),
			Identity: &ServerAuthenticationIdentityModel{
				ClaimAliases:     types.MapNull(types.StringType),
				EnforcedClaims:   types.ListNull(types.StringType),
				IdentityPath:     types.StringValue("/old/path"),
				TokenAppProperty: types.StringValue("old-claim"),
			},
		},
	}

	auth := &swaclient.ServerAuthentication{
		Type: "jwt",
		Data: map[string]any{
			"sub": "workload-sub",
		},
	}

	err := syncServerAuthFromResponse(ctx, state, auth)
	assert.NoError(t, err)
	assert.True(t, state.Auth.PublicKeys.IsNull())
	assert.Nil(t, state.Auth.Identity)
}

// TEMPORARY: guards the fallback that keeps the prior subject when the API
// omits `sub` from the authentication data. Remove alongside the fallback in
// syncServerAuthFromResponse once the API echoes `sub` back.
func TestSyncServerAuthFromResponse_MissingSubjectPreservesPriorValue(t *testing.T) {
	ctx := context.Background()
	state := &ServerResourceModel{
		Auth: &ServerAuthenticationModel{
			Subject: types.StringValue("system:serviceaccount:swa-e2e:swa-server"),
		},
	}

	auth := &swaclient.ServerAuthentication{
		Type: "jwt",
		Data: map[string]any{
			"audience": "conjur",
		},
	}

	err := syncServerAuthFromResponse(ctx, state, auth)
	assert.NoError(t, err)
	assert.Equal(t, "system:serviceaccount:swa-e2e:swa-server", state.Auth.Subject.ValueString())
}

func TestSyncServerAuthFromResponse_PublicKeysMarshalError(t *testing.T) {
	state := &ServerResourceModel{}
	auth := &swaclient.ServerAuthentication{
		Type: "jwt",
		Data: map[string]any{
			"sub":         "workload-sub",
			"public_keys": map[string]any{"bad": make(chan int)},
		},
	}

	err := syncServerAuthFromResponse(context.Background(), state, auth)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal auth.public_keys")
}

func TestSyncServerAuthFromResponse_NilAuthClearsExistingState(t *testing.T) {
	state := &ServerResourceModel{
		Auth: &ServerAuthenticationModel{
			Type:    types.StringValue("JWT"),
			Subject: types.StringValue("stale-sub"),
		},
	}

	err := syncServerAuthFromResponse(context.Background(), state, nil)
	assert.NoError(t, err)
	assert.Nil(t, state.Auth)
}
