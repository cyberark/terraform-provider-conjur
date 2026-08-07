package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	swaclient "github.com/cyberark/terraform-provider-conjur/internal/swa/client"
	swamocks "github.com/cyberark/terraform-provider-conjur/internal/swa/client/mocks"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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
				m.On("PostServerWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
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
				m.On("PostServerWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
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
				m.On("PostServerWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(&swaclient.PostServerResponse{
						HTTPResponse: makeHTTPResponse(http.StatusConflict),
						Body:         []byte(`{"message":"already exists"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error creating server",
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
				m.On("PostServerWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
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
				m.On("PostServerWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
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
				m.On("PostServerWithResponse", context.Background(), "prod.example.org", "prod-servers", &swaclient.PostServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
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
			name: "both jwks_uri and public_keys set",
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
					PublicKeys: types.StringValue(`{"type":"jwks","value":{"keys":[]}}`),
				},
			},
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Only one of auth.jwks_uri or auth.public_keys",
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
				m.On("DeleteServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "my-server", &swaclient.DeleteServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("DeleteServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "my-server", &swaclient.DeleteServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("DeleteServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "my-server", &swaclient.DeleteServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("DeleteServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "my-server", &swaclient.DeleteServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
	// The PATCH /servers/{name} operation updates the mutable auth data fields
	// (jwks_uri/public_keys/issuer/audience) in place. Immutable fields
	// (type/subject/ca_cert) are handled by RequiresReplace at plan time, so the
	// resource's Update never has to reject them — it simply PATCHes the plan.
	tests := []struct {
		name          string
		plan          ServerResourceModel
		setupMock     func(*swamocks.MockClientWithResponsesInterface)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful in-place update of jwks_uri",
			plan: ServerResourceModel{
				ID:            types.StringValue("prod.example.org/prod-servers/my-server"),
				Name:          types.StringValue("my-server"),
				ServerGroupID: types.StringValue("prod.example.org/prod-servers"),
				Auth: &ServerAuthenticationModel{
					Type:       types.StringValue("JWT"),
					Subject:    types.StringValue("my-workload"),
					Issuer:     types.StringValue("https://issuer.example.org"),
					Audience:   types.StringNull(),
					JWKSURI:    types.StringValue("https://issuer.example.org/.well-known/jwks-v2.json"),
					CACert:     types.StringNull(),
					PublicKeys: types.StringNull(),
				},
			},
			setupMock: func(m *swamocks.MockClientWithResponsesInterface) {
				m.On("PatchServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "my-server", &swaclient.PatchServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(&swaclient.PatchServerResponse{
						HTTPResponse: makeHTTPResponse(http.StatusOK),
						ApplicationxSecretsmgrV2JSON200: &swaclient.ServerResponse{
							Name:           "my-server",
							Authentication: &swaclient.ServerAuthentication{Type: "jwt", Data: map[string]any{"sub": "my-workload", "jwks_uri": "https://issuer.example.org/.well-known/jwks-v2.json"}},
						},
					}, nil)
			},
			expectedError: false,
		},
		{
			name: "invalid server ID format",
			plan: ServerResourceModel{
				ID:            types.StringValue("invalid-no-slash"),
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
			setupMock:     func(m *swamocks.MockClientWithResponsesInterface) {},
			expectedError: true,
			errorContains: "Invalid server ID",
		},
		{
			name: "API error during update",
			plan: ServerResourceModel{
				ID:            types.StringValue("prod.example.org/prod-servers/my-server"),
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
				m.On("PatchServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "my-server", &swaclient.PatchServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(nil, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Error updating server",
		},
		{
			name: "non-200 status code",
			plan: ServerResourceModel{
				ID:            types.StringValue("prod.example.org/prod-servers/my-server"),
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
				m.On("PatchServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "my-server", &swaclient.PatchServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}, mock.Anything).
					Return(&swaclient.PatchServerResponse{
						HTTPResponse: makeHTTPResponse(http.StatusBadRequest),
						Body:         []byte(`{"message":"invalid input"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error updating server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := swamocks.NewMockClientWithResponsesInterface(t)
			tt.setupMock(mockClient)

			r := &ServerResource{client: mockClient}

			req := resource.UpdateRequest{
				Plan:  newPlanWithSchema(getServerTestSchema()),
				State: newStateWithSchema(getServerTestSchema()),
			}
			resp := &resource.UpdateResponse{
				State: newStateWithSchema(getServerTestSchema()),
			}

			ctx := context.Background()
			if diags := req.Plan.Set(ctx, &tt.plan); diags.HasError() {
				t.Fatalf("failed to set plan: %v", diags)
			}
			if diags := req.State.Set(ctx, &tt.plan); diags.HasError() {
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
				m.On("GetServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "my-server", &swaclient.GetServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
				m.On("GetServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "missing-server", &swaclient.GetServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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
			name: "non-200 status code during read",
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
				m.On("GetServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "my-server", &swaclient.GetServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
					Return(&swaclient.GetServerResponse{
						HTTPResponse: makeHTTPResponse(http.StatusInternalServerError),
						Body:         []byte(`{"message":"internal error"}`),
					}, nil)
			},
			expectedError: true,
			errorContains: "Error reading server",
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
				m.On("GetServerWithResponse", context.Background(), "prod.example.org", "prod-servers", "my-server", &swaclient.GetServerParams{Accept: swaclient.ApplicationxSecretsmgrV2Json}).
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

func TestPreferPriorJSONString(t *testing.T) {
	compact := `{"type":"jwks","value":{"keys":[{"kid":"abc"}]}}`
	pretty := "{\n  \"type\": \"jwks\",\n  \"value\": {\"keys\": [{\"kid\": \"abc\"}]}\n}"
	reordered := `{"value":{"keys":[{"kid":"abc"}]},"type":"jwks"}`
	different := `{"type":"jwks","value":{"keys":[{"kid":"xyz"}]}}`

	tests := []struct {
		name     string
		prior    types.String
		incoming types.String
		want     types.String
	}{
		{
			name:     "semantically equal compact vs pretty — returns prior",
			prior:    types.StringValue(compact),
			incoming: types.StringValue(pretty),
			want:     types.StringValue(compact),
		},
		{
			name:     "semantically equal different key order — returns prior",
			prior:    types.StringValue(compact),
			incoming: types.StringValue(reordered),
			want:     types.StringValue(compact),
		},
		{
			name:     "semantically equal identical strings — returns prior",
			prior:    types.StringValue(compact),
			incoming: types.StringValue(compact),
			want:     types.StringValue(compact),
		},
		{
			name:     "genuinely different JSON — returns incoming",
			prior:    types.StringValue(compact),
			incoming: types.StringValue(different),
			want:     types.StringValue(different),
		},
		{
			name:     "prior null — returns incoming",
			prior:    types.StringNull(),
			incoming: types.StringValue(compact),
			want:     types.StringValue(compact),
		},
		{
			name:     "prior unknown — returns incoming",
			prior:    types.StringUnknown(),
			incoming: types.StringValue(compact),
			want:     types.StringValue(compact),
		},
		{
			name:     "incoming null — returns incoming",
			prior:    types.StringValue(compact),
			incoming: types.StringNull(),
			want:     types.StringNull(),
		},
		{
			name:     "incoming unknown — returns incoming",
			prior:    types.StringValue(compact),
			incoming: types.StringUnknown(),
			want:     types.StringUnknown(),
		},
		{
			name:     "invalid JSON in incoming — returns incoming",
			prior:    types.StringValue(compact),
			incoming: types.StringValue("not-json"),
			want:     types.StringValue("not-json"),
		},
		{
			name:     "invalid JSON in prior — returns incoming",
			prior:    types.StringValue("not-json"),
			incoming: types.StringValue(compact),
			want:     types.StringValue(compact),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, preferPriorJSONString(tt.prior, tt.incoming))
		})
	}
}

func TestJSONEquivalentPlanModifier_WiresPreferPriorJSONString(t *testing.T) {
	compact := `{"type":"jwks","value":{"keys":[{"kid":"abc"}]}}`
	pretty := "{\n  \"type\": \"jwks\",\n  \"value\": {\"keys\": [{\"kid\": \"abc\"}]}\n}"

	m := jsonEquivalentPlanModifier{}
	req := planmodifier.StringRequest{
		StateValue:  types.StringValue(compact),
		ConfigValue: types.StringValue(pretty),
		PlanValue:   types.StringValue(pretty),
	}
	resp := &planmodifier.StringResponse{PlanValue: types.StringValue(pretty)}
	m.PlanModifyString(context.Background(), req, resp)

	assert.Equal(t, types.StringValue(compact), resp.PlanValue)
	assert.False(t, resp.Diagnostics.HasError())
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

// --- Schema plan modifier tests ---

func TestServerResource_Schema_RequiresReplace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &ServerResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	// auth itself no longer forces replacement — the PATCH operation updates mutable
	// auth data in place. Only the immutable leaves (type/subject/ca_cert/identity)
	// carry RequiresReplace; the mutable ones (jwks_uri/issuer/audience/public_keys)
	// route through Update.
	tests := []struct {
		attrPath      []string
		shouldReplace bool
	}{
		{[]string{"name"}, true},
		{[]string{"server_group_id"}, true},
		{[]string{"auth"}, false},
		{[]string{"id"}, false},
		{[]string{"authn_id"}, false},
		{[]string{"auth", "type"}, true},
		{[]string{"auth", "subject"}, true},
		{[]string{"auth", "ca_cert"}, true},
		{[]string{"auth", "identity"}, true},
		{[]string{"auth", "jwks_uri"}, false},
		{[]string{"auth", "issuer"}, false},
		{[]string{"auth", "audience"}, false},
		{[]string{"auth", "public_keys"}, false},
	}

	const requiresReplaceDesc = "If the value of this attribute changes, Terraform will destroy and recreate the resource."

	planModifiersHaveReplace := func(attr schema.Attribute) bool {
		switch a := attr.(type) {
		case schema.StringAttribute:
			for _, pm := range a.PlanModifiers {
				if pm.Description(ctx) == requiresReplaceDesc {
					return true
				}
			}
		case schema.SingleNestedAttribute:
			for _, pm := range a.PlanModifiers {
				if pm.Description(ctx) == requiresReplaceDesc {
					return true
				}
			}
		}
		return false
	}

	for _, tc := range tests {
		t.Run(strings.Join(tc.attrPath, "."), func(t *testing.T) {
			t.Parallel()
			attr := schemaResp.Schema.Attributes[tc.attrPath[0]]
			assert.NotNil(t, attr, "attribute %q not found in schema", tc.attrPath[0])

			if len(tc.attrPath) == 2 {
				nested, ok := attr.(schema.SingleNestedAttribute)
				require.True(t, ok, "attribute %q is not a nested attribute", tc.attrPath[0])
				attr = nested.Attributes[tc.attrPath[1]]
				assert.NotNil(t, attr, "nested attribute %q not found", tc.attrPath[1])
			}

			hasRequiresReplace := planModifiersHaveReplace(attr)
			if tc.shouldReplace {
				assert.True(t, hasRequiresReplace, "attribute %v should have RequiresReplace", tc.attrPath)
			} else {
				assert.False(t, hasRequiresReplace, "attribute %v should NOT have RequiresReplace", tc.attrPath)
			}
		})
	}
}

// --- Lifecycle tests (mock-client acceptance style) ---

func TestServerResource_CreateAndDelete(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	mockClient.EXPECT().
		PostServerWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything, mock.Anything).
		Return(&swaclient.PostServerResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.CreateServerResponse{
				Name:           "test-server",
				AuthnId:        "dGVzdC10ZC10ZXN0LXNnLXRlc3Qtc2VydmVy",
				Authentication: swaclient.CreateServerAuthentication{Type: "JWT"},
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetServerWithResponse(mock.Anything, "test-td", "test-sg", "test-server", mock.Anything).
		Return(&swaclient.GetServerResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerResponse{
				Name:           "test-server",
				Authentication: &swaclient.ServerAuthentication{Type: "jwt", Data: map[string]any{"sub": "my-workload", "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"}},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteServerWithResponse(mock.Anything, "test-td", "test-sg", "test-server", mock.Anything).
		Return(&swaclient.DeleteServerResponse{
			HTTPResponse: makeHTTPResponse(http.StatusNoContent),
		}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server" "test" {
  name            = "test-server"
  server_group_id = "test-td/test-sg"
  auth = {
    type     = "JWT"
    subject  = "my-workload"
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
  }
}
`,
				Check: tfresource.ComposeTestCheckFunc(
					tfresource.TestCheckResourceAttr("conjur_swa_server.test", "name", "test-server"),
					tfresource.TestCheckResourceAttr("conjur_swa_server.test", "id", "test-td/test-sg/test-server"),
					tfresource.TestCheckResourceAttr("conjur_swa_server.test", "authn_id", "dGVzdC10ZC10ZXN0LXNnLXRlc3Qtc2VydmVy"),
				),
			},
		},
	})
}

func TestServerResource_AuthChange_RequiresReplace(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	// Create is called once; step 2 uses PlanOnly so no apply fires.
	mockClient.EXPECT().
		PostServerWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything, mock.Anything).
		Return(&swaclient.PostServerResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.CreateServerResponse{
				Name:           "test-server",
				AuthnId:        "dGVzdC10ZC10ZXN0LXNnLXRlc3Qtc2VydmVy",
				Authentication: swaclient.CreateServerAuthentication{Type: "JWT"},
			},
		}, nil).Times(1)

	// All Reads return the original URI. After the replace the framework's post-apply
	// refresh would show a diff (state has certs-CHANGED from the plan, Read returns
	// certs), so we use PlanOnly on step 2 to verify the replace is planned without
	// executing the apply — which avoids the post-apply consistency check.
	mockClient.EXPECT().
		GetServerWithResponse(mock.Anything, "test-td", "test-sg", "test-server", mock.Anything).
		Return(&swaclient.GetServerResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerResponse{
				Name:           "test-server",
				Authentication: &swaclient.ServerAuthentication{Type: "jwt", Data: map[string]any{"sub": "my-workload", "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"}},
			},
		}, nil).Maybe()

	// Delete called once for final teardown after step 1.
	mockClient.EXPECT().
		DeleteServerWithResponse(mock.Anything, "test-td", "test-sg", "test-server", mock.Anything).
		Return(&swaclient.DeleteServerResponse{
			HTTPResponse: makeHTTPResponse(http.StatusNoContent),
		}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server" "test" {
  name            = "test-server"
  server_group_id = "test-td/test-sg"
  auth = {
    type     = "JWT"
    subject  = "my-workload"
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
  }
}
`,
				Check: tfresource.TestCheckResourceAttr("conjur_swa_server.test", "name", "test-server"),
			},
			{
				// Changing the immutable subject must produce a replace plan, not an update.
				// (Mutable auth data such as jwks_uri routes through Update instead — see
				// TestServerResource_Update.) PlanOnly skips apply so we avoid mock complexity
				// around the post-replace read.
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				Config: `
resource "conjur_swa_server" "test" {
  name            = "test-server"
  server_group_id = "test-td/test-sg"
  auth = {
    type     = "JWT"
    subject  = "my-workload-CHANGED"
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
  }
}
`,
			},
		},
	})
}

func TestServerResource_NameChange_RequiresReplace(t *testing.T) {
	t.Parallel()

	mockClient := swamocks.NewMockClientWithResponsesInterface(t)

	mockClient.EXPECT().
		PostServerWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything,
			mock.MatchedBy(func(body swaclient.PostServerJSONRequestBody) bool { return body.Name == "server-1" })).
		Return(&swaclient.PostServerResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.CreateServerResponse{
				Name:           "server-1",
				AuthnId:        "dGVzdC1zZXJ2ZXItMQ==",
				Authentication: swaclient.CreateServerAuthentication{Type: "JWT"},
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		PostServerWithResponse(mock.Anything, "test-td", "test-sg", mock.Anything,
			mock.MatchedBy(func(body swaclient.PostServerJSONRequestBody) bool { return body.Name == "server-2" })).
		Return(&swaclient.PostServerResponse{
			HTTPResponse: makeHTTPResponse(http.StatusCreated),
			ApplicationxSecretsmgrV2JSON201: &swaclient.CreateServerResponse{
				Name:           "server-2",
				AuthnId:        "dGVzdC1zZXJ2ZXItMg==",
				Authentication: swaclient.CreateServerAuthentication{Type: "JWT"},
			},
		}, nil).Times(1)

	mockClient.EXPECT().
		GetServerWithResponse(mock.Anything, "test-td", "test-sg", "server-1", mock.Anything).
		Return(&swaclient.GetServerResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerResponse{
				Name:           "server-1",
				Authentication: &swaclient.ServerAuthentication{Type: "jwt", Data: map[string]any{"sub": "my-workload", "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"}},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		GetServerWithResponse(mock.Anything, "test-td", "test-sg", "server-2", mock.Anything).
		Return(&swaclient.GetServerResponse{
			HTTPResponse: makeHTTPResponse(http.StatusOK),
			ApplicationxSecretsmgrV2JSON200: &swaclient.ServerResponse{
				Name:           "server-2",
				Authentication: &swaclient.ServerAuthentication{Type: "jwt", Data: map[string]any{"sub": "my-workload", "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"}},
			},
		}, nil).Maybe()

	mockClient.EXPECT().
		DeleteServerWithResponse(mock.Anything, "test-td", "test-sg", "server-1", mock.Anything).
		Return(&swaclient.DeleteServerResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	mockClient.EXPECT().
		DeleteServerWithResponse(mock.Anything, "test-td", "test-sg", "server-2", mock.Anything).
		Return(&swaclient.DeleteServerResponse{HTTPResponse: makeHTTPResponse(http.StatusNoContent)}, nil).Times(1)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: swaTestProviderFactories(t, mockClient),
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "conjur_swa_server" "test" {
  name            = "server-1"
  server_group_id = "test-td/test-sg"
  auth = {
    type     = "JWT"
    subject  = "my-workload"
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
  }
}
`,
				Check: tfresource.TestCheckResourceAttr("conjur_swa_server.test", "name", "server-1"),
			},
			{
				Config: `
resource "conjur_swa_server" "test" {
  name            = "server-2"
  server_group_id = "test-td/test-sg"
  auth = {
    type     = "JWT"
    subject  = "my-workload"
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
  }
}
`,
				Check: tfresource.TestCheckResourceAttr("conjur_swa_server.test", "name", "server-2"),
			},
		},
	})
}
