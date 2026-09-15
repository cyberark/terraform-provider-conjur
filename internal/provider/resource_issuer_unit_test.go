package provider

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
// created_at/modified_at timestamps onto the model, and populates data.AWS only for aws-type
// issuers (setting it to nil otherwise).
func TestParseIssuerResponse(t *testing.T) {
	tests := []struct {
		name          string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &IssuerResource{}
			var data IssuerResourceModel

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
		name          string
		data          IssuerResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectError   bool
		errorContains string
		expectRemoved bool
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
			expectRemoved: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)
			r := &IssuerResource{client: mockV2}

			req := resource.ReadRequest{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			resp := &resource.ReadResponse{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			req.State.Set(context.Background(), &tt.data)

			r.Read(context.Background(), req, resp)

			assertDiagOutcome(t, resp.Diagnostics, tt.expectError, tt.errorContains)
			if tt.expectRemoved {
				assert.True(t, resp.State.Raw.IsNull())
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)
			r := &IssuerResource{client: mockV2}

			req := resource.UpdateRequest{Plan: tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			resp := &resource.UpdateResponse{State: tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{}, nil), Schema: getIssuerTestSchema()}}
			req.Plan.Set(context.Background(), &tt.data)

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
