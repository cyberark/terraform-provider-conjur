package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
	"unicode"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestBuildIssuerPayload verifies that buildIssuerPayload encodes secret refs as
// {"id": "..."} objects (via SecretRef), not as bare strings.
func TestBuildIssuerPayload(t *testing.T) {
	r := &IssuerResource{}
	data := &IssuerResourceModel{
		Id:     types.StringValue("my-issuer"),
		MaxTTL: types.Int32Value(3600),
	}
	aws := &AWSIssuerModel{
		AccessKeyIdSecretRef:     types.StringValue("data/aws/key"),
		SecretAccessKeySecretRef: types.StringValue("data/aws/secret"),
	}

	payload := r.buildIssuerPayload(data, aws)

	assert.Equal(t, "my-issuer", payload.ID)
	assert.Equal(t, 3600, payload.MaxTTL)
	assert.Equal(t, "aws", payload.Type)
	assert.Equal(t, SecretRef{Id: "data/aws/key"}, payload.Data["access_key_id_secret_ref"])
	assert.Equal(t, SecretRef{Id: "data/aws/secret"}, payload.Data["secret_access_key_secret_ref"])
}

// TestBuildIssuerUpdatePayload verifies the same wire shape for update payloads.
func TestBuildIssuerUpdatePayload(t *testing.T) {
	r := &IssuerResource{}
	data := &IssuerResourceModel{
		Id:     types.StringValue("my-issuer"),
		MaxTTL: types.Int32Value(7200),
	}
	aws := &AWSIssuerModel{
		AccessKeyIdSecretRef:     types.StringValue("data/aws/key2"),
		SecretAccessKeySecretRef: types.StringValue("data/aws/secret2"),
	}

	payload := r.buildIssuerUpdatePayload(data, aws)

	require.NotNil(t, payload.MaxTTL)
	assert.Equal(t, 7200, *payload.MaxTTL)
	assert.Equal(t, SecretRef{Id: "data/aws/key2"}, payload.Data["access_key_id_secret_ref"])
	assert.Equal(t, SecretRef{Id: "data/aws/secret2"}, payload.Data["secret_access_key_secret_ref"])
}

// TestAWSIssuerDataFromMap verifies round-trip correctness: a map as returned by the Conjur API
// (i.e. JSON-decoded map[string]any) is correctly converted to AWSIssuerData.
func TestAWSIssuerDataFromMap(t *testing.T) {
	tests := []struct {
		name        string
		input       map[string]any
		expected    AWSIssuerData
		expectError bool
	}{
		{
			name: "valid aws data",
			input: map[string]any{
				"access_key_id_secret_ref":     map[string]any{"id": "data/aws/key"},
				"secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret"},
			},
			expected: AWSIssuerData{
				AccessKeyIdSecretRef:     SecretRef{Id: "data/aws/key"},
				SecretAccessKeySecretRef: SecretRef{Id: "data/aws/secret"},
			},
		},
		{
			name:     "empty map returns zero-value struct",
			input:    map[string]any{},
			expected: AWSIssuerData{},
		},
		{
			name: "missing id field yields empty string",
			input: map[string]any{
				"access_key_id_secret_ref":     map[string]any{},
				"secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret"},
			},
			expected: AWSIssuerData{
				AccessKeyIdSecretRef:     SecretRef{Id: ""},
				SecretAccessKeySecretRef: SecretRef{Id: "data/aws/secret"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := awsIssuerDataFromMap(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

// TestParseIssuerResponse verifies that parseIssuerResponse maps the ID, MaxTTL and the
// created_at/modified_at timestamps onto the model, populates data.AWS for aws-type issuers, and
// rejects responses that are for another issuer, out of range, incomplete or of an unsupported type.
func TestParseIssuerResponse(t *testing.T) {
	validAWSData := map[string]any{
		"access_key_id_secret_ref":     map[string]any{"id": "data/aws/key"},
		"secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret"},
	}
	tests := []struct {
		name          string
		requestedID   string // defaults to issuer.ID
		issuer        conjurapi.Issuer
		expectAWS     bool
		expectedKeyID string
		expectedKey   string
		expectError   bool
		errorContains string
	}{
		{
			name: "aws issuer with timestamps",
			issuer: conjurapi.Issuer{
				ID: "my-issuer", MaxTTL: 3600, Type: "aws",
				CreatedAt:  "2024-01-02T03:04:05Z",
				ModifiedAt: "2024-02-03T04:05:06Z",
				Data: map[string]any{
					"access_key_id_secret_ref":     map[string]any{"id": "data/aws/key"},
					"secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret"},
				},
			},
			expectAWS:     true,
			expectedKeyID: "data/aws/key",
			expectedKey:   "data/aws/secret",
		},
		{
			name: "non-aws issuer type is rejected",
			issuer: conjurapi.Issuer{
				ID: "other-issuer", MaxTTL: 900, Type: "gcp",
				CreatedAt:  "2024-03-04T05:06:07Z",
				ModifiedAt: "2024-04-05T06:07:08Z",
			},
			expectError:   true,
			errorContains: "unsupported issuer type",
		},
		{
			name: "empty issuer type is rejected",
			issuer: conjurapi.Issuer{
				ID: "no-times", MaxTTL: 1800, Type: "",
				CreatedAt:  "",
				ModifiedAt: "",
			},
			expectError:   true,
			errorContains: "unsupported issuer type",
		},
		{
			name:          "response for another issuer ID is rejected",
			requestedID:   "my-issuer",
			issuer:        conjurapi.Issuer{ID: "other-issuer", MaxTTL: 3600, Type: "aws", Data: validAWSData},
			expectError:   true,
			errorContains: `the response is for issuer ID "other-issuer" instead of the requested "my-issuer"`,
		},
		{
			name:          "response with an empty issuer ID is rejected",
			requestedID:   "my-issuer",
			issuer:        conjurapi.Issuer{ID: "", MaxTTL: 3600, Type: "aws", Data: validAWSData},
			expectError:   true,
			errorContains: `the response is for issuer ID "" instead of the requested "my-issuer"`,
		},
		{
			name:          "max_ttl above the int32 range is rejected",
			issuer:        conjurapi.Issuer{ID: "my-issuer", MaxTTL: math.MaxInt32 + 1, Type: "aws", Data: validAWSData},
			expectError:   true,
			errorContains: "out of range",
		},
		{
			name:          "max_ttl below the int32 range is rejected",
			issuer:        conjurapi.Issuer{ID: "my-issuer", MaxTTL: math.MinInt32 - 1, Type: "aws", Data: validAWSData},
			expectError:   true,
			errorContains: "out of range",
		},
		{
			name: "empty access key ID secret ref is rejected",
			issuer: conjurapi.Issuer{ID: "my-issuer", MaxTTL: 3600, Type: "aws", Data: map[string]any{
				"access_key_id_secret_ref":     map[string]any{"id": ""},
				"secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret"},
			}},
			expectError:   true,
			errorContains: "missing the AWS secret refs",
		},
		{
			name: "missing secret access key secret ref is rejected",
			issuer: conjurapi.Issuer{ID: "my-issuer", MaxTTL: 3600, Type: "aws", Data: map[string]any{
				"access_key_id_secret_ref": map[string]any{"id": "data/aws/key"},
			}},
			expectError:   true,
			errorContains: "missing the AWS secret refs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &IssuerResource{}
			requestedID := tt.requestedID
			if requestedID == "" {
				requestedID = tt.issuer.ID
			}
			data := IssuerResourceModel{Id: types.StringValue(requestedID)}

			err := r.parseIssuerResponse(context.Background(), tt.issuer, &data)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.issuer.ID, data.Id.ValueString())
			assert.Equal(t, int32(tt.issuer.MaxTTL), data.MaxTTL.ValueInt32())
			assert.False(t, data.CreatedAt.IsNull())
			assert.False(t, data.ModifiedAt.IsNull())
			assert.Equal(t, tt.issuer.CreatedAt, data.CreatedAt.ValueString())
			assert.Equal(t, tt.issuer.ModifiedAt, data.ModifiedAt.ValueString())

			if tt.expectAWS {
				require.False(t, data.AWS.IsNull())
				var diags diag.Diagnostics
				aws := modelFromObject[AWSIssuerModel](context.Background(), data.AWS, &diags)
				require.False(t, diags.HasError())
				assert.Equal(t, tt.expectedKeyID, aws.AccessKeyIdSecretRef.ValueString())
				assert.Equal(t, tt.expectedKey, aws.SecretAccessKeySecretRef.ValueString())
			} else {
				assert.True(t, data.AWS.IsNull())
			}
		})
	}
}

func TestIssuerResource_Create(t *testing.T) {
	maxTTL := 3600
	tests := []struct {
		name          string
		data          IssuerResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectError   bool
		errorContains string
	}{
		{
			name: "successful AWS issuer creation",
			data: IssuerResourceModel{
				Id:     types.StringValue("my-issuer"),
				MaxTTL: types.Int32Value(int32(maxTTL)),
				AWS:    awsTestObject("data/aws/key", "data/aws/secret"),
			},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("CreateIssuer", mock.MatchedBy(func(i conjurapi.Issuer) bool {
					return i.ID == "my-issuer" && i.MaxTTL == maxTTL && i.Type == "aws" &&
						i.Data["access_key_id_secret_ref"] == SecretRef{Id: "data/aws/key"}
				})).Return(conjurapi.Issuer{
					ID: "my-issuer", MaxTTL: maxTTL, Type: "aws",
					Data: map[string]any{
						"access_key_id_secret_ref":     map[string]any{"id": "data/aws/key"},
						"secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret"},
					},
				}, nil)
			},
		},
		{
			name: "API error during creation",
			data: IssuerResourceModel{
				Id:     types.StringValue("bad-issuer"),
				MaxTTL: types.Int32Value(int32(maxTTL)),
				AWS:    awsTestObject("data/aws/key", "data/aws/secret"),
			},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("CreateIssuer", mock.Anything).Return(conjurapi.Issuer{}, fmt.Errorf("permission denied"))
			},
			expectError:   true,
			errorContains: "Unable to create issuer",
		},
		{
			// aws was unknown at plan time (so ValidateConfig skipped it) and resolved to null by
			// apply: Create must reject it instead of sending a type-less payload to the API.
			name: "aws resolving to null is rejected",
			data: IssuerResourceModel{
				Id:     types.StringValue("no-type-issuer"),
				MaxTTL: types.Int32Value(int32(maxTTL)),
				AWS:    types.ObjectNull(awsIssuerAttrTypes),
			},
			setupMock:     func(m *mocks.MockClientV2) {},
			expectError:   true,
			errorContains: "Exactly one issuer type block must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)
			r := &IssuerResource{client: mockV2}

			req := resource.CreateRequest{Plan: tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			resp := &resource.CreateResponse{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			req.Plan.Set(context.Background(), &tt.data)

			r.Create(context.Background(), req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectError, tt.errorContains)
			mockV2.AssertExpectations(t)
		})
	}
}

func TestIssuerResource_Read(t *testing.T) {
	maxTTL := 3600
	tests := []struct {
		name            string
		data            IssuerResourceModel
		setupMock       func(*mocks.MockClientV2)
		expectError     bool
		errorContains   string
		expectRemoved   bool
		warningContains string
	}{
		{
			name: "successful read",
			data: IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("data/aws/key", "data/aws/secret")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("Issuer", "my-issuer").Return(conjurapi.Issuer{
					ID: "my-issuer", MaxTTL: maxTTL, Type: "aws",
					Data: map[string]any{
						"access_key_id_secret_ref":     map[string]any{"id": "data/aws/key"},
						"secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret"},
					},
				}, nil)
			},
		},
		{
			name: "API error (non-not-found)",
			data: IssuerResourceModel{Id: types.StringValue("missing"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("Issuer", "missing").Return(conjurapi.Issuer{}, fmt.Errorf("500 internal server error"))
			},
			expectError:   true,
			errorContains: "Unable to read issuer",
		},
		{
			name: "issuer not found - removes from state",
			data: IssuerResourceModel{Id: types.StringValue("gone"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("Issuer", "gone").Return(conjurapi.Issuer{}, &response.ConjurError{Code: http.StatusNotFound})
			},
			expectRemoved:   true,
			warningContains: "Issuer Not Found",
		},
		{
			name: "wrapped not found error - removes from state",
			data: IssuerResourceModel{Id: types.StringValue("gone"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("Issuer", "gone").Return(conjurapi.Issuer{}, fmt.Errorf("reading issuer: %w", &response.ConjurError{Code: http.StatusNotFound}))
			},
			expectRemoved:   true,
			warningContains: "Issuer Not Found",
		},
		{
			name: "unauthorized is a hard error",
			data: IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("Issuer", "my-issuer").Return(conjurapi.Issuer{}, &response.ConjurError{Code: http.StatusUnauthorized, Message: "Unauthorized"})
			},
			expectError:   true,
			errorContains: "status 401: Unauthorized",
		},
		{
			name: "forbidden is a hard error",
			data: IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("Issuer", "my-issuer").Return(conjurapi.Issuer{}, &response.ConjurError{Code: http.StatusForbidden, Message: "Forbidden"})
			},
			expectError:   true,
			errorContains: "status 403: Forbidden",
		},
		{
			name: "internal server error is a hard error",
			data: IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("Issuer", "my-issuer").Return(conjurapi.Issuer{}, &response.ConjurError{Code: http.StatusInternalServerError, Message: "Internal Server Error"})
			},
			expectError:   true,
			errorContains: "status 500: Internal Server Error",
		},
		{
			// The state must keep the requested ID: writing the server's ID would make a later
			// replacement delete an issuer the configuration never referenced.
			name: "response for another issuer ID does not overwrite the state",
			data: IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("data/aws/key", "data/aws/secret")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("Issuer", "my-issuer").Return(conjurapi.Issuer{
					ID: "other-issuer", MaxTTL: maxTTL, Type: "aws",
					Data: map[string]any{
						"access_key_id_secret_ref":     map[string]any{"id": "data/aws/key"},
						"secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret"},
					},
				}, nil)
			},
			expectError:   true,
			errorContains: "Unable to parse read issuer response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)
			r := &IssuerResource{client: mockV2}

			req := resource.ReadRequest{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			req.State.Set(context.Background(), &tt.data)
			// The framework seeds the response state with the prior state.
			resp := &resource.ReadResponse{State: tfsdk.State{Raw: req.State.Raw.Copy(), Schema: getIssuerTestSchema()}}

			r.Read(context.Background(), req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectError, tt.errorContains)
			assert.Equal(t, tt.expectRemoved, resp.State.Raw.IsNull())
			if tt.warningContains != "" {
				assertWarningContains(t, resp.Diagnostics, tt.warningContains)
			}
			if tt.expectError {
				var state IssuerResourceModel
				require.False(t, resp.State.Get(context.Background(), &state).HasError())
				assert.Equal(t, tt.data, state, "state must be left untouched on error")
			}
			mockV2.AssertExpectations(t)
		})
	}
}

func TestIssuerResource_Update(t *testing.T) {
	maxTTL := 7200
	tests := []struct {
		name          string
		data          IssuerResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectError   bool
		errorContains string
	}{
		{
			name: "successful update",
			data: IssuerResourceModel{
				Id:     types.StringValue("my-issuer"),
				MaxTTL: types.Int32Value(int32(maxTTL)),
				AWS:    awsTestObject("data/aws/key", "data/aws/secret"),
			},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("UpdateIssuer", "my-issuer", mock.MatchedBy(func(u conjurapi.IssuerUpdate) bool {
					return u.MaxTTL != nil && *u.MaxTTL == maxTTL &&
						u.Data["access_key_id_secret_ref"] == SecretRef{Id: "data/aws/key"}
				})).Return(conjurapi.Issuer{
					ID: "my-issuer", MaxTTL: maxTTL, Type: "aws",
					Data: map[string]any{
						"access_key_id_secret_ref":     map[string]any{"id": "data/aws/key"},
						"secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret"},
					},
				}, nil)
			},
		},
		{
			name: "API error during update",
			data: IssuerResourceModel{
				Id:     types.StringValue("bad-issuer"),
				MaxTTL: types.Int32Value(int32(maxTTL)),
				AWS:    awsTestObject("x", "y"),
			},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("UpdateIssuer", "bad-issuer", mock.Anything).Return(conjurapi.Issuer{}, fmt.Errorf("forbidden"))
			},
			expectError:   true,
			errorContains: "Unable to update issuer",
		},
		{
			// aws was unknown at plan time (so ValidateConfig skipped it) and resolved to null by
			// apply: Update must reject it instead of issuing a PATCH that silently drops Data and
			// leaves stale credentials attached server-side.
			name: "aws resolving to null is rejected",
			data: IssuerResourceModel{
				Id:     types.StringValue("no-type-issuer"),
				MaxTTL: types.Int32Value(int32(maxTTL)),
				AWS:    types.ObjectNull(awsIssuerAttrTypes),
			},
			setupMock:     func(m *mocks.MockClientV2) {},
			expectError:   true,
			errorContains: "Exactly one issuer type block must be specified",
		},
		{
			// max_ttl was unknown at plan time (so ModifyPlan skipped the check) and resolved to a
			// lower value than the current one by apply.
			name:          "max_ttl resolving to a decrease is rejected",
			data:          IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(1800), AWS: awsTestObject("data/aws/key", "data/aws/secret")},
			setupMock:     func(m *mocks.MockClientV2) {},
			expectError:   true,
			errorContains: "max_ttl cannot be decreased (current: 3600, new: 1800)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)
			r := &IssuerResource{client: mockV2}

			req := resource.UpdateRequest{Plan: tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}, State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			resp := &resource.UpdateResponse{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			req.Plan.Set(context.Background(), &tt.data)
			req.State.Set(context.Background(), &IssuerResourceModel{Id: tt.data.Id, MaxTTL: types.Int32Value(3600), AWS: awsTestObject("data/aws/key", "data/aws/secret")})

			r.Update(context.Background(), req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectError, tt.errorContains)
			mockV2.AssertExpectations(t)
		})
	}
}

func TestIssuerResource_Delete(t *testing.T) {
	maxTTL := 3600
	tests := []struct {
		name            string
		data            IssuerResourceModel
		setupMock       func(*mocks.MockClientV2)
		expectError     bool
		errorContains   string
		expectWarning   bool
		warningContains string
	}{
		{
			name:      "successful deletion",
			data:      IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) { m.On("DeleteIssuer", "my-issuer", true).Return(nil) },
		},
		{
			name:          "API error during deletion",
			data:          IssuerResourceModel{Id: types.StringValue("bad-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock:     func(m *mocks.MockClientV2) { m.On("DeleteIssuer", "bad-issuer", true).Return(fmt.Errorf("boom")) },
			expectError:   true,
			errorContains: "Unable to delete issuer",
		},
		{
			name: "issuer already deleted only raises a warning",
			data: IssuerResourceModel{Id: types.StringValue("gone-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("DeleteIssuer", "gone-issuer", true).Return(&response.ConjurError{Code: http.StatusNotFound})
			},
			expectWarning:   true,
			warningContains: "Issuer Not Found",
		},
		{
			name: "wrapped not found error only raises a warning",
			data: IssuerResourceModel{Id: types.StringValue("gone-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("DeleteIssuer", "gone-issuer", true).Return(fmt.Errorf("deleting issuer: %w", &response.ConjurError{Code: http.StatusNotFound}))
			},
			expectWarning:   true,
			warningContains: "Issuer Not Found",
		},
		{
			name: "unauthorized is a hard error",
			data: IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("DeleteIssuer", "my-issuer", true).Return(&response.ConjurError{Code: http.StatusUnauthorized, Message: "Unauthorized"})
			},
			expectError:   true,
			errorContains: "status 401: Unauthorized",
		},
		{
			name: "forbidden is a hard error",
			data: IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("DeleteIssuer", "my-issuer", true).Return(&response.ConjurError{Code: http.StatusForbidden, Message: "Forbidden"})
			},
			expectError:   true,
			errorContains: "status 403: Forbidden",
		},
		{
			name: "internal server error is a hard error",
			data: IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(int32(maxTTL)), AWS: awsTestObject("x", "y")},
			setupMock: func(m *mocks.MockClientV2) {
				m.On("DeleteIssuer", "my-issuer", true).Return(&response.ConjurError{Code: http.StatusInternalServerError, Message: "Internal Server Error"})
			},
			expectError:   true,
			errorContains: "status 500: Internal Server Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)
			r := &IssuerResource{client: mockV2}

			req := resource.DeleteRequest{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			resp := &resource.DeleteResponse{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			req.State.Set(context.Background(), &tt.data)

			r.Delete(context.Background(), req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectError, tt.errorContains)
			if tt.expectWarning {
				assert.NotEmpty(t, resp.Diagnostics.Warnings(), "expected a warning diagnostic, got none")
				assertWarningContains(t, resp.Diagnostics, tt.warningContains)
			}
			mockV2.AssertExpectations(t)
		})
	}
}

func TestIssuerResource_ModifyPlan(t *testing.T) {
	base := IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(3600), AWS: awsTestObject("data/aws/key", "data/aws/secret")}
	tests := []struct {
		name              string
		planId            string
		stateId           string
		planMaxTTL        int32
		stateMaxTTL       int32
		planMaxTTLUnknown bool
		stateMaxTTLNull   bool
		isCreate          bool
		isDestroy         bool
		expectError       bool
		errorContains     string
	}{
		{name: "max_ttl decreased is rejected", planMaxTTL: 900, stateMaxTTL: 7200, expectError: true, errorContains: "max_ttl cannot be decreased"},
		{name: "max_ttl increased is allowed", planMaxTTL: 9000, stateMaxTTL: 3600},
		{name: "max_ttl unchanged is allowed", planMaxTTL: 3600, stateMaxTTL: 3600},
		{name: "rename with lower max_ttl is allowed (replacement)", planId: "renamed-issuer", stateId: "my-issuer", planMaxTTL: 900, stateMaxTTL: 7200},
		{name: "rename with higher max_ttl is allowed", planId: "renamed-issuer", stateId: "my-issuer", planMaxTTL: 9000, stateMaxTTL: 3600},
		{name: "unknown max_ttl is deferred to apply", planMaxTTLUnknown: true, stateMaxTTL: 7200},
		{name: "null state max_ttl (imported, not yet refreshed) is allowed", planMaxTTL: 900, stateMaxTTLNull: true},
		{name: "create (null state) is skipped", planMaxTTL: 900, isCreate: true},
		{name: "destroy (null plan) is skipped", stateMaxTTL: 3600, isDestroy: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &IssuerResource{}
			req := resource.ModifyPlanRequest{
				Plan:  tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()},
				State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()},
			}
			resp := &resource.ModifyPlanResponse{}

			if !tt.isCreate {
				stateModel := base
				if tt.stateId != "" {
					stateModel.Id = types.StringValue(tt.stateId)
				}
				stateModel.MaxTTL = types.Int32Value(tt.stateMaxTTL)
				if tt.stateMaxTTLNull {
					stateModel = IssuerResourceModel{Id: stateModel.Id, MaxTTL: types.Int32Null(), AWS: types.ObjectNull(awsIssuerAttrTypes)}
				}
				req.State.Set(context.Background(), &stateModel)
			}
			if !tt.isDestroy {
				planModel := base
				if tt.planId != "" {
					planModel.Id = types.StringValue(tt.planId)
				}
				if tt.planMaxTTLUnknown {
					planModel.MaxTTL = types.Int32Unknown()
				} else {
					planModel.MaxTTL = types.Int32Value(tt.planMaxTTL)
				}
				req.Plan.Set(context.Background(), &planModel)
			}

			r.ModifyPlan(context.Background(), req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectError, tt.errorContains)
		})
	}
}

func TestIssuerResource_ValidateConfig(t *testing.T) {
	tests := []struct {
		name          string
		data          IssuerResourceModel
		expectError   bool
		errorContains string
	}{
		{
			name: "valid AWS issuer",
			data: IssuerResourceModel{
				Id:     types.StringValue("my-issuer"),
				MaxTTL: types.Int32Value(3600),
				AWS:    awsTestObject("data/aws/key", "data/aws/secret"),
			},
		},
		{
			name: "empty access_key_id_secret_ref",
			data: IssuerResourceModel{
				Id:     types.StringValue("my-issuer"),
				MaxTTL: types.Int32Value(3600),
				AWS:    awsTestObject("", "data/aws/secret"),
			},
			expectError:   true,
			errorContains: "AWS access key ID secret ref",
		},
		{
			name: "empty secret_access_key_secret_ref",
			data: IssuerResourceModel{
				Id:     types.StringValue("my-issuer"),
				MaxTTL: types.Int32Value(3600),
				AWS:    awsTestObject("data/aws/key", ""),
			},
			expectError:   true,
			errorContains: "AWS secret access key secret ref",
		},
		{
			// aws wholly Unknown (e.g. HCL like `aws = var.enable ? {...} : null` where var.enable
			// can't be resolved statically) must not make ValidateConfig hard-error trying to decode
			// the Unknown object into AWSIssuerModel; the inner-ref checks are deferred to apply time
			// instead. It still counts as one configured issuer type, so no "exactly one" error fires.
			name: "unknown aws does not trigger a decode crash",
			data: IssuerResourceModel{
				Id:     types.StringValue("my-issuer"),
				MaxTTL: types.Int32Value(3600),
				AWS:    types.ObjectUnknown(awsIssuerAttrTypes),
			},
		},
		{
			name: "no issuer type configured",
			data: IssuerResourceModel{
				Id:     types.StringValue("my-issuer"),
				MaxTTL: types.Int32Value(3600),
				AWS:    types.ObjectNull(awsIssuerAttrTypes),
			},
			expectError:   true,
			errorContains: "Exactly one issuer type block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &IssuerResource{}
			req := resource.ValidateConfigRequest{Config: buildIssuerConfigFromModel(tt.data)}
			resp := &resource.ValidateConfigResponse{}

			r.ValidateConfig(context.Background(), req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectError, tt.errorContains)
		})
	}
}

// TestIssuerResource_IDValidator verifies that the id schema validators reject IDs that would be
// unsafe in the API path (dot segments, slashes, query strings, whitespace) or empty.
func TestIssuerResource_IDValidator(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{name: "letters, digits, +, - and _ are accepted", id: "my-issuer_1+x"},
		{name: "dot segment is rejected", id: ".", expectError: true},
		{name: "parent dot segment is rejected", id: "..", expectError: true},
		{name: "slash is rejected", id: "a/b", expectError: true},
		{name: "space is rejected", id: "a b", expectError: true},
		{name: "query string is rejected", id: "a?x=1", expectError: true},
		{name: "empty ID is rejected", id: "", expectError: true},
	}

	idAttr, ok := getIssuerTestSchema().Attributes["id"].(schema.StringAttribute)
	require.True(t, ok)
	require.NotEmpty(t, idAttr.Validators)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validator.StringRequest{Path: path.Root("id"), ConfigValue: types.StringValue(tt.id)}
			var diags diag.Diagnostics
			for _, v := range idAttr.Validators {
				resp := &validator.StringResponse{}
				v.ValidateString(context.Background(), req, resp)
				diags.Append(resp.Diagnostics...)
			}

			assertDiagOutcome(t, diags, tt.expectError, issuerIDPatternDescription)
		})
	}
}

func TestIssuerResource_ImportState(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{name: "valid ID is imported", id: "my-issuer_1+x"},
		{name: "dot segment is rejected", id: ".", expectError: true},
		{name: "parent dot segment is rejected", id: "..", expectError: true},
		{name: "slash is rejected", id: "a/b", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &IssuerResource{}
			req := resource.ImportStateRequest{ID: tt.id}
			resp := &resource.ImportStateResponse{State: tfsdk.State{Raw: tftypes.NewValue(getIssuerTestSchema().Type().TerraformType(context.Background()), nil), Schema: getIssuerTestSchema()}}

			r.ImportState(context.Background(), req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectError, "Invalid import ID")
			if tt.expectError {
				assert.True(t, resp.State.Raw.IsNull(), "state must not be set for a rejected import ID")
				return
			}
			var id types.String
			require.False(t, resp.State.GetAttribute(context.Background(), path.Root("id"), &id).HasError())
			assert.Equal(t, tt.id, id.ValueString())
		})
	}
}

// TestIssuerResource_Create_ParseFailureAddsReconcileHint verifies that when CreateIssuer succeeds
// but its response can't be used, no state is saved and the error tells the user to reconcile the
// untracked issuer in Secrets Manager.
func TestIssuerResource_Create_ParseFailureAddsReconcileHint(t *testing.T) {
	var decoded conjurapi.Issuer
	syntaxErr := json.Unmarshal([]byte("<html>"), &decoded)
	typeErr := json.Unmarshal([]byte(`{"max_ttl":"x"}`), &decoded)
	tests := []struct {
		name          string
		created       conjurapi.Issuer
		createErr     error
		errorContains string
	}{
		{
			name:          "response body is not JSON",
			createErr:     syntaxErr,
			errorContains: syntaxErr.Error(),
		},
		{
			name:          "response body has the wrong JSON types",
			createErr:     typeErr,
			errorContains: typeErr.Error(),
		},
		{
			name: "response for another issuer ID",
			created: conjurapi.Issuer{
				ID: "server-chosen", MaxTTL: 3600, Type: "aws", CreatedAt: "2024-01-02T03:04:05Z", ModifiedAt: "2024-01-02T03:04:05Z",
				Data: map[string]any{
					"access_key_id_secret_ref":     map[string]any{"id": "data/aws/key"},
					"secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret"},
				},
			},
			errorContains: `the response is for issuer ID "server-chosen" instead of the requested "my-issuer"`,
		},
		{
			name:          "unsupported issuer type",
			created:       conjurapi.Issuer{ID: "my-issuer", MaxTTL: 3600, Type: "gcp", CreatedAt: "2024-01-02T03:04:05Z", ModifiedAt: "2024-01-02T03:04:05Z"},
			errorContains: `unsupported issuer type "gcp"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			planned := IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(3600), AWS: awsTestObject("data/aws/key", "data/aws/secret"), CreatedAt: types.StringUnknown(), ModifiedAt: types.StringUnknown()}
			mockV2 := mocks.NewMockClientV2(t)
			mockV2.On("CreateIssuer", mock.Anything).Return(tt.created, tt.createErr)

			resp := runIssuerCreate(&IssuerResource{client: mockV2}, planned)

			assertDiagOutcome(t, resp.Diagnostics, true, `The create request for issuer "my-issuer" succeeded`)
			assertDiagContains(t, resp.Diagnostics, "check Secrets Manager and import or delete it")
			assertDiagContains(t, resp.Diagnostics, tt.errorContains)
			assert.True(t, resp.State.Raw.IsNull())
			mockV2.AssertExpectations(t)
		})
	}
}

// TestIssuerResource_ApplyRevalidatesIDAndMaxTTL verifies that id and max_ttl values that were unknown
// at plan time (so the plan-time validators skipped them) are re-checked before any API call.
func TestIssuerResource_ApplyRevalidatesIDAndMaxTTL(t *testing.T) {
	tests := []struct {
		name          string
		id            string
		maxTTL        int32
		errorContains string
	}{
		{name: "id with path traversal", id: "../admin", maxTTL: 3600, errorContains: issuerIDPatternDescription},
		{name: "id with slash", id: "a/b", maxTTL: 3600, errorContains: issuerIDPatternDescription},
		{name: "empty id", id: "", maxTTL: 3600, errorContains: issuerIDPatternDescription},
		{name: "max_ttl below range", id: "my-issuer", maxTTL: 899, errorContains: "Max TTL must be between 900 and 43200"},
		{name: "max_ttl above range", id: "my-issuer", maxTTL: 43_201, errorContains: "Max TTL must be between 900 and 43200"},
	}

	for _, tt := range tests {
		data := IssuerResourceModel{Id: types.StringValue(tt.id), MaxTTL: types.Int32Value(tt.maxTTL), AWS: awsTestObject("data/aws/key", "data/aws/secret")}
		t.Run("create/"+tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			resp := runIssuerCreate(&IssuerResource{client: mockV2}, data)
			assertDiagOutcome(t, resp.Diagnostics, true, tt.errorContains)
			mockV2.AssertNotCalled(t, "CreateIssuer", mock.Anything)
		})
		t.Run("update/"+tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			req := resource.UpdateRequest{Plan: tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}, State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			req.Plan.Set(context.Background(), &data)
			req.State.Set(context.Background(), &IssuerResourceModel{Id: data.Id, MaxTTL: types.Int32Value(900), AWS: data.AWS})
			resp := &resource.UpdateResponse{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			(&IssuerResource{client: mockV2}).Update(context.Background(), req, resp)
			assertDiagOutcome(t, resp.Diagnostics, true, tt.errorContains)
			mockV2.AssertNotCalled(t, "UpdateIssuer", mock.Anything, mock.Anything)
		})
	}
}

// TestIssuerResource_Update_ParseFailureAddsRefreshHint verifies that when UpdateIssuer is applied
// server-side but its response can't be used, the prior state is left untouched and the error tells
// the user how to reconcile it.
func TestIssuerResource_Update_ParseFailureAddsRefreshHint(t *testing.T) {
	var decoded conjurapi.Issuer
	syntaxErr := json.Unmarshal([]byte("<html>"), &decoded)
	typeErr := json.Unmarshal([]byte(`{"max_ttl":"x"}`), &decoded)
	awsData := map[string]any{"access_key_id_secret_ref": map[string]any{"id": "data/aws/key2"}, "secret_access_key_secret_ref": map[string]any{"id": "data/aws/secret2"}}
	tests := []struct {
		name          string
		updated       conjurapi.Issuer
		updateErr     error
		errorContains string
	}{
		{name: "response body is not JSON", updateErr: syntaxErr, errorContains: syntaxErr.Error()},
		{name: "response body has the wrong JSON types", updateErr: typeErr, errorContains: typeErr.Error()},
		{name: "response for another issuer ID", updated: conjurapi.Issuer{ID: "server-chosen", MaxTTL: 7200, Type: "aws", Data: awsData}, errorContains: `the response is for issuer ID "server-chosen" instead of the requested "my-issuer"`},
		{name: "response is missing the secret refs", updated: conjurapi.Issuer{ID: "my-issuer", MaxTTL: 7200, Type: "aws"}, errorContains: "the response is missing the AWS secret refs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prior := IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(3600), AWS: awsTestObject("data/aws/key", "data/aws/secret"), CreatedAt: types.StringValue("2024-01-02T03:04:05Z"), ModifiedAt: types.StringValue("2024-01-02T03:04:05Z")}
			planned := IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(7200), AWS: awsTestObject("data/aws/key2", "data/aws/secret2"), CreatedAt: prior.CreatedAt, ModifiedAt: types.StringUnknown()}
			mockV2 := mocks.NewMockClientV2(t)
			mockV2.On("UpdateIssuer", "my-issuer", mock.Anything).Return(tt.updated, tt.updateErr)

			req := resource.UpdateRequest{Plan: tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}, State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			req.Plan.Set(context.Background(), &planned)
			req.State.Set(context.Background(), &prior)
			resp := &resource.UpdateResponse{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			resp.State.Set(context.Background(), &prior)

			(&IssuerResource{client: mockV2}).Update(context.Background(), req, resp)

			assertDiagOutcome(t, resp.Diagnostics, true, `The update request for issuer "my-issuer" succeeded`)
			assertDiagContains(t, resp.Diagnostics, "terraform apply -refresh-only")
			assertDiagContains(t, resp.Diagnostics, tt.errorContains)
			var got IssuerResourceModel
			require.False(t, resp.State.Get(context.Background(), &got).HasError())
			assert.Equal(t, prior, got)
			mockV2.AssertExpectations(t)
		})
	}
}

// TestIssuerResource_ErrorDetailIsSanitized verifies that server-supplied text (API error messages
// and values echoed in parse errors) is stripped of control and bidi characters and truncated before
// it is placed into a diagnostic.
func TestIssuerResource_ErrorDetailIsSanitized(t *testing.T) {
	data := IssuerResourceModel{Id: types.StringValue("my-issuer"), MaxTTL: types.Int32Value(3600), AWS: awsTestObject("data/aws/key", "data/aws/secret")}
	serverErr := &response.ConjurError{Code: http.StatusInternalServerError, Message: "boom\x1b[31m\r\n\u202edcba" + strings.Repeat("x", 1024)}
	tests := []struct {
		name           string
		setupMock      func(*mocks.MockClientV2)
		run            func(*IssuerResource) diag.Diagnostics
		detailContains []string
	}{
		{
			name:           "create API error",
			setupMock:      func(m *mocks.MockClientV2) { m.On("CreateIssuer", mock.Anything).Return(conjurapi.Issuer{}, serverErr) },
			run:            func(r *IssuerResource) diag.Diagnostics { return runIssuerCreate(r, data).Diagnostics },
			detailContains: []string{"Unable to create issuer, got error: status 500: boom [31m   dcba", "... (truncated)"},
		},
		{
			name:           "read API error",
			setupMock:      func(m *mocks.MockClientV2) { m.On("Issuer", "my-issuer").Return(conjurapi.Issuer{}, serverErr) },
			run:            func(r *IssuerResource) diag.Diagnostics { return runIssuerRead(r, data).Diagnostics },
			detailContains: []string{"Unable to read issuer, got error: status 500: boom [31m   dcba", "... (truncated)"},
		},
		{
			name: "read response with an unsupported issuer type",
			setupMock: func(m *mocks.MockClientV2) {
				m.On("Issuer", "my-issuer").Return(conjurapi.Issuer{ID: "my-issuer", MaxTTL: 3600, Type: "gcp\x1b[2J\n\u202e" + strings.Repeat("y", 1024)}, nil)
			},
			run:            func(r *IssuerResource) diag.Diagnostics { return runIssuerRead(r, data).Diagnostics },
			detailContains: []string{"Unable to parse read issuer response, got error: unsupported issuer type", "... (truncated)"},
		},
		{
			name: "read response for another issuer ID",
			setupMock: func(m *mocks.MockClientV2) {
				m.On("Issuer", "my-issuer").Return(conjurapi.Issuer{ID: "evil\u202e\x1b[2J\nid", MaxTTL: 3600, Type: "aws"}, nil)
			},
			run:            func(r *IssuerResource) diag.Diagnostics { return runIssuerRead(r, data).Diagnostics },
			detailContains: []string{`the response is for issuer ID "evil  [2J id" instead of the requested "my-issuer"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			diags := tt.run(&IssuerResource{client: mockV2})

			require.Len(t, diags.Errors(), 1)
			detail := diags.Errors()[0].Detail()
			assert.False(t, strings.ContainsFunc(detail, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) }), "detail contains control characters: %q", detail)
			for _, s := range tt.detailContains {
				assert.Contains(t, detail, s)
			}
			mockV2.AssertExpectations(t)
		})
	}
}

func runIssuerCreate(r *IssuerResource, data IssuerResourceModel) *resource.CreateResponse {
	req := resource.CreateRequest{Plan: tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
	resp := &resource.CreateResponse{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
	req.Plan.Set(context.Background(), &data)
	r.Create(context.Background(), req, resp)
	return resp
}

func runIssuerRead(r *IssuerResource, data IssuerResourceModel) *resource.ReadResponse {
	req := resource.ReadRequest{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
	req.State.Set(context.Background(), &data)
	resp := &resource.ReadResponse{State: tfsdk.State{Raw: req.State.Raw.Copy(), Schema: getIssuerTestSchema()}}
	r.Read(context.Background(), req, resp)
	return resp
}

func buildIssuerConfigFromModel(data IssuerResourceModel) tfsdk.Config {
	plan := tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}
	plan.Set(context.Background(), &data)
	return tfsdk.Config{Raw: plan.Raw, Schema: getIssuerTestSchema()}
}

// getIssuerTestSchema returns the schema used to build tfsdk.Plan / tfsdk.State in tests.
func getIssuerTestSchema() schema.Schema {
	r := &IssuerResource{}
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	return resp.Schema
}

// awsTestObject builds the types.Object that the "aws" attribute now holds, from the given refs.
func awsTestObject(keyID, secret string) types.Object {
	return types.ObjectValueMust(awsIssuerAttrTypes, map[string]attr.Value{
		"access_key_id_secret_ref":     types.StringValue(keyID),
		"secret_access_key_secret_ref": types.StringValue(secret),
	})
}
