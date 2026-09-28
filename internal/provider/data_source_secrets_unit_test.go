package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretsDataSource_Read_NilClient verifies that when the provider is not configured
// (nil client) Read emits the "Provider client not configured" warning, does not error, and
// does not populate state - it returns before any BatchRetrieveSecrets call.
func TestSecretsDataSource_Read_NilClient(t *testing.T) {
	d := &SecretsDataSource{}

	testSchema := getSecretsDataSourceTestSchema()
	req := datasource.ReadRequest{
		Config: tfsdk.Config{
			Raw:    secretsBatchConfigValue([]string{"data/a"}, types.BoolNull()),
			Schema: testSchema,
		},
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{
			Raw:    tftypes.NewValue(tftypes.Object{}, nil),
			Schema: testSchema,
		},
	}

	d.Read(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError(), "expected no error diagnostics, got: %v", resp.Diagnostics.Errors())
	assertWarningContains(t, resp.Diagnostics, "Provider client not configured")
	assert.True(t, resp.State.Raw.IsNull(), "expected state to not be populated")
}

// TestSecretsDataSource_NamesValidators exercises the validators declared on the data source's
// "names" attribute. These run at the framework validation layer before Read, so we pull them off
// the real schema and invoke them directly to keep the test in sync with the schema definition.
func TestSecretsDataSource_NamesValidators(t *testing.T) {
	runNamesListValidators(t, getSecretsDataSourceTestSchema().Attributes["names"].(schema.ListAttribute).Validators)
}

func TestSecretsDataSource_Read(t *testing.T) {
	for _, tt := range batchSecretsReadTestCases() {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			d := &SecretsDataSource{client: mockV2}

			testSchema := getSecretsDataSourceTestSchema()
			req := datasource.ReadRequest{
				Config: tfsdk.Config{
					Raw:    secretsBatchConfigValue(tt.names, tt.failOnError),
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

			assertDiagOutcome(t, resp.Diagnostics, tt.expectedError, tt.errorContains)
			if tt.expectedWarning != "" {
				assertWarningContains(t, resp.Diagnostics, tt.expectedWarning)
			}
			if tt.expectedError {
				assert.True(t, resp.State.Raw.IsNull(), "expected state to not be populated on error")
			} else {
				var result secretsModel
				diags := resp.State.Get(ctx, &result)
				require.False(t, diags.HasError(), diags)
				gotValues := map[string]string{}
				diags = result.Values.ElementsAs(ctx, &gotValues, false)
				require.False(t, diags.HasError(), diags)
				assert.Equal(t, tt.expectedValues, gotValues)
			}

			mockV2.AssertExpectations(t)
		})
	}
}

// batchSecretsReadTestCase drives both the data source Read and the ephemeral Open tests,
// since both delegate to the shared batchRetrieveSecretsToMap helper.
type batchSecretsReadTestCase struct {
	name            string
	names           []string
	failOnError     types.Bool
	setupMock       func(*mocks.MockClientV2)
	expectedError   bool
	errorContains   string
	expectedWarning string
	expectedValues  map[string]string
}

func batchSecretsReadTestCases() []batchSecretsReadTestCase {
	return []batchSecretsReadTestCase{
		{
			name:  "all secrets retrieved successfully",
			names: []string{"db/user", "db/password"},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user", "db/password"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/user", Value: "admin", Status: 200},
						{ID: "db/password", Value: "s3cr3t", Status: 200},
					},
				}, nil)
			},
			expectedValues: map[string]string{"db/user": "admin", "db/password": "s3cr3t"},
		},
		{
			name:  "empty secret value is retrieved",
			names: []string{"db/empty"},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/empty"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/empty", Value: "", Status: 200},
					},
				}, nil)
			},
			expectedValues: map[string]string{"db/empty": ""},
		},
		{
			name:        "partial failure with fail_on_error false only warns and maps successes",
			names:       []string{"db/ok", "db/denied"},
			failOnError: types.BoolValue(false),
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/ok", "db/denied"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/ok", Value: "v", Status: 200},
						{ID: "db/denied", Status: 403, Description: "Forbidden"},
					},
				}, nil)
			},
			expectedWarning: "Failed to retrieve secret",
			expectedValues:  map[string]string{"db/ok": "v"},
		},
		{
			name:        "partial failure with fail_on_error unset defaults to hard-fail",
			names:       []string{"db/ok", "db/denied"},
			failOnError: types.BoolNull(),
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/ok", "db/denied"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/ok", Value: "v", Status: 200},
						{ID: "db/denied", Status: 403, Description: "Forbidden"},
					},
				}, nil)
			},
			expectedError: true,
			errorContains: "Failed to retrieve secret",
		},
		{
			name:        "partial failure with fail_on_error true errors",
			names:       []string{"db/ok", "db/denied"},
			failOnError: types.BoolValue(true),
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/ok", "db/denied"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/ok", Value: "v", Status: 200},
						{ID: "db/denied", Status: 403, Description: "Forbidden"},
					},
				}, nil)
			},
			expectedError: true,
			errorContains: "Failed to retrieve secret",
		},
		{
			name:  "top-level error is surfaced",
			names: []string{"db/user"},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user"}).Return(nil, fmt.Errorf("500 Internal Server Error"))
			},
			expectedError: true,
			errorContains: "Failed to retrieve secrets",
		},
		{
			name:  "nil response without error is surfaced",
			names: []string{"db/user"},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user"}).Return(nil, nil)
			},
			expectedError: true,
			errorContains: "empty response from server",
		},
		{
			name:        "partial failure with fail_on_error unknown defaults to hard-fail",
			names:       []string{"db/ok", "db/denied"},
			failOnError: types.BoolUnknown(),
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/ok", "db/denied"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/ok", Value: "v", Status: 200},
						{ID: "db/denied", Status: 403, Description: "Forbidden"},
					},
				}, nil)
			},
			expectedError: true,
			errorContains: "Failed to retrieve secret",
		},
		{
			name:  "unrequested IDs in the response are not added to values",
			names: []string{"db/user"},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/user", Value: "admin", Status: 200},
						{ID: "db/extra", Value: "extra", Status: 200},
					},
				}, nil)
			},
			expectedWarning: "Unexpected secrets in response",
			expectedValues:  map[string]string{"db/user": "admin"},
		},
		{
			name:        "duplicate IDs in the response error even with fail_on_error false",
			names:       []string{"db/user"},
			failOnError: types.BoolValue(false),
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/user", Value: "admin", Status: 200},
						{ID: "db/user", Value: "injected", Status: 200},
					},
				}, nil)
			},
			expectedError: true,
			errorContains: "Duplicate secrets in response",
		},
		{
			name:        "success and failure for the same ID error even with fail_on_error false",
			names:       []string{"db/user"},
			failOnError: types.BoolValue(false),
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/user", Value: "admin", Status: 200},
						{ID: "db/user", Status: 403, Description: "Forbidden"},
					},
				}, nil)
			},
			expectedError: true,
			errorContains: "Duplicate secrets in response",
		},
		{
			name:  "top-level Conjur error includes the status and a sanitized, truncated message",
			names: []string{"db/user"},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user"}).Return(nil, &response.ConjurError{Code: 502, Message: "<html>\x1b[31mBad Gateway\n" + strings.Repeat("x", 4096)})
			},
			expectedError: true,
			errorContains: "status 502: <html> [31mBad Gateway " + strings.Repeat("x", maxServerTextLength-len("<html>\x1b[31mBad Gateway\n")) + "... (truncated)",
		},
		{
			name:  "qualified IDs in the response with fail_on_error unset are a mismatch",
			names: []string{"db/user"},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "conjur:variable:db/user", Value: "admin", Status: 200},
					},
				}, nil)
			},
			expectedError: true,
			errorContains: "Mismatch between requested and retrieved secrets",
		},
		{
			name:        "qualified IDs in the response with fail_on_error false warn and are not added to values",
			names:       []string{"db/user"},
			failOnError: types.BoolValue(false),
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "conjur:variable:db/user", Value: "admin", Status: 200},
					},
				}, nil)
			},
			expectedWarning: "Mismatch between requested and retrieved secrets",
			expectedValues:  map[string]string{},
		},
		{
			name:        "count mismatch with fail_on_error false only warns",
			names:       []string{"db/user", "db/password"},
			failOnError: types.BoolValue(false),
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user", "db/password"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/user", Value: "admin", Status: 200},
					},
				}, nil)
			},
			expectedWarning: "Mismatch between requested and retrieved secrets",
			expectedValues:  map[string]string{"db/user": "admin"},
		},
		{
			name:        "count mismatch with fail_on_error unset defaults to hard-fail",
			names:       []string{"db/user", "db/password"},
			failOnError: types.BoolNull(),
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user", "db/password"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/user", Value: "admin", Status: 200},
					},
				}, nil)
			},
			expectedError: true,
			errorContains: "Mismatch between requested and retrieved secrets",
		},
		{
			name:        "count mismatch with fail_on_error true errors",
			names:       []string{"db/user", "db/password"},
			failOnError: types.BoolValue(true),
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("BatchRetrieveSecrets", []string{"db/user", "db/password"}).Return(&conjurapi.BatchSecretResponse{
					Secrets: []conjurapi.SecretValue{
						{ID: "db/user", Value: "admin", Status: 200},
					},
				}, nil)
			},
			expectedError: true,
			errorContains: "Mismatch between requested and retrieved secrets",
		},
	}
}

// TestCheckForMismatch exercises checkForMismatch directly, covering missing secrets, a same-length
// mismatch (the set differs while the counts match), and extra secrets in the response, for both
// fail_on_error values. It asserts the boolean return value alongside the emitted diagnostics.
func TestCheckForMismatch(t *testing.T) {
	response := func(ids ...string) []conjurapi.SecretValue {
		secrets := make([]conjurapi.SecretValue, len(ids))
		for i, id := range ids {
			secrets[i] = conjurapi.SecretValue{ID: id, Value: "v", Status: 200}
		}
		return secrets
	}

	tests := []struct {
		name            string
		requestedNames  []string
		response        []conjurapi.SecretValue
		failOnError     bool
		expectedResult  bool
		expectedError   bool
		expectedWarning bool
		messageContains string
	}{
		{
			name:           "exact match adds nothing and returns true",
			requestedNames: []string{"db/user", "db/password"},
			response:       response("db/user", "db/password"),
			failOnError:    true,
			expectedResult: true,
		},
		{
			name:            "fail_on_error true, missing secret adds an error",
			requestedNames:  []string{"db/user", "db/password"},
			response:        response("db/user"),
			failOnError:     true,
			expectedResult:  false,
			expectedError:   true,
			messageContains: `"db/password"`,
		},
		{
			name:            "fail_on_error true, same length with a mismatch adds an error and an unexpected-secret warning",
			requestedNames:  []string{"db/user", "db/password"},
			response:        response("db/user", "db/other"),
			failOnError:     true,
			expectedResult:  false,
			expectedError:   true,
			expectedWarning: true,
			messageContains: `"db/password"`,
		},
		{
			name:            "fail_on_error true, more secrets than requested adds a warning",
			requestedNames:  []string{"db/user"},
			response:        response("db/user", "db/extra"),
			failOnError:     true,
			expectedResult:  true,
			expectedWarning: true,
			messageContains: `"db/extra"`,
		},
		{
			name:            "fail_on_error true, duplicate secrets add an error",
			requestedNames:  []string{"db/user"},
			response:        response("db/user", "db/user"),
			failOnError:     true,
			expectedResult:  false,
			expectedError:   true,
			messageContains: "Duplicate secrets in response",
		},
		{
			name:            "unexpected secret IDs are sanitized and capped",
			requestedNames:  []string{"db/user"},
			response:        response("db/user", "a\x1b[31m\nb", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "e10", "e11"),
			failOnError:     true,
			expectedResult:  true,
			expectedWarning: true,
			messageContains: `12 secret(s) that weren't requested and were ignored: "a [31m b", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9" and 2 more`,
		},
		{
			name:            "fail_on_error false, missing secret adds a warning",
			requestedNames:  []string{"db/user", "db/password"},
			response:        response("db/user"),
			failOnError:     false,
			expectedResult:  true,
			expectedWarning: true,
			messageContains: `"db/password"`,
		},
		{
			name:            "fail_on_error false, same length with a mismatch adds a warning",
			requestedNames:  []string{"db/user", "db/password"},
			response:        response("db/user", "db/other"),
			failOnError:     false,
			expectedResult:  true,
			expectedWarning: true,
			messageContains: `"db/password"`,
		},
		{
			name:            "fail_on_error false, more secrets than requested adds a warning",
			requestedNames:  []string{"db/user"},
			response:        response("db/user", "db/extra"),
			failOnError:     false,
			expectedResult:  true,
			expectedWarning: true,
			messageContains: `"db/extra"`,
		},
		{
			name:            "fail_on_error false, duplicate secrets add an error",
			requestedNames:  []string{"db/user"},
			response:        response("db/user", "db/user"),
			failOnError:     false,
			expectedResult:  false,
			expectedError:   true,
			messageContains: "Duplicate secrets in response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diags diag.Diagnostics

			result := checkForMismatch(tt.requestedNames, tt.response, tt.failOnError, &diags)

			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, tt.expectedError, diags.HasError(), "unexpected error diagnostics: %v", diags.Errors())
			assert.Equal(t, tt.expectedWarning, len(diags.Warnings()) > 0, "unexpected warning diagnostics: %v", diags.Warnings())
			if tt.messageContains != "" {
				if tt.expectedError {
					assertDiagContains(t, diags, tt.messageContains)
				} else {
					assertWarningContains(t, diags, tt.messageContains)
				}
			}
		})
	}
}

// TestBatchRetrieveSecretsToMap_FailedEntryValueNeverLeaks verifies that the value carried by a failed
// (non-2xx) entry never reaches the diagnostics or values, for both fail_on_error values.
func TestBatchRetrieveSecretsToMap_FailedEntryValueNeverLeaks(t *testing.T) {
	const canary = "leak-canary"

	for _, failOnError := range []bool{true, false} {
		t.Run(fmt.Sprintf("fail_on_error %t", failOnError), func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			mockV2.On("BatchRetrieveSecrets", []string{"db/ok", "db/denied"}).Return(&conjurapi.BatchSecretResponse{
				Secrets: []conjurapi.SecretValue{
					{ID: "db/ok", Value: "v", Status: 200},
					{ID: "db/denied", Value: canary, Status: 403, Description: "Forbidden"},
				},
			}, nil)

			ctx := context.Background()
			config := tfsdk.Config{
				Raw:    secretsBatchConfigValue([]string{"db/ok", "db/denied"}, types.BoolValue(failOnError)),
				Schema: getSecretsDataSourceTestSchema(),
			}
			var diags diag.Diagnostics

			data, ok := batchRetrieveSecretsToMap(ctx, mockV2, config, &diags)

			assert.Equal(t, !failOnError, ok)
			require.NotEmpty(t, diags)
			for _, d := range diags {
				assert.NotContains(t, d.Summary(), canary)
				assert.NotContains(t, d.Detail(), canary)
			}
			if ok {
				gotValues := map[string]string{}
				require.False(t, data.Values.ElementsAs(ctx, &gotValues, false).HasError())
				assert.Equal(t, map[string]string{"db/ok": "v"}, gotValues)
			}
		})
	}
}

// TestBatchRetrieveSecretsToMap_DescriptionIsSanitized verifies that a server-supplied per-secret
// description is stripped of control characters and truncated before it is placed into a diagnostic.
func TestBatchRetrieveSecretsToMap_DescriptionIsSanitized(t *testing.T) {
	mockV2 := mocks.NewMockClientV2(t)
	mockV2.On("BatchRetrieveSecrets", []string{"db/denied"}).Return(&conjurapi.BatchSecretResponse{
		Secrets: []conjurapi.SecretValue{
			{ID: "db/denied", Status: 403, Description: "Forbidden\r\n\x1b[2J" + strings.Repeat("x", 4096)},
		},
	}, nil)

	config := tfsdk.Config{
		Raw:    secretsBatchConfigValue([]string{"db/denied"}, types.BoolNull()),
		Schema: getSecretsDataSourceTestSchema(),
	}
	var diags diag.Diagnostics

	_, ok := batchRetrieveSecretsToMap(context.Background(), mockV2, config, &diags)

	assert.False(t, ok)
	require.Len(t, diags.Errors(), 1)
	detail := diags.Errors()[0].Detail()
	assert.True(t, strings.HasPrefix(detail, "Forbidden   [2J"), detail)
	assert.True(t, strings.HasSuffix(detail, "... (truncated)"), detail)
	assert.Len(t, detail, maxServerTextLength+len("... (truncated)"))
}

// secretsBatchConfigValue builds a tftypes config value matching the shared batch secrets
// schema (names/values/fail_on_error). values is computed, so it is null in config. It is
// shared by the data source Read and ephemeral Open unit tests.
func secretsBatchConfigValue(names []string, failOnError types.Bool) tftypes.Value {
	nameVals := make([]tftypes.Value, len(names))
	for i, n := range names {
		nameVals[i] = tftypes.NewValue(tftypes.String, n)
	}

	failOnErrorVal := tftypes.NewValue(tftypes.Bool, nil)
	if failOnError.IsUnknown() {
		failOnErrorVal = tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)
	} else if !failOnError.IsNull() {
		failOnErrorVal = tftypes.NewValue(tftypes.Bool, failOnError.ValueBool())
	}

	return tftypes.NewValue(
		tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"names":         tftypes.List{ElementType: tftypes.String},
				"values":        tftypes.Map{ElementType: tftypes.String},
				"fail_on_error": tftypes.Bool,
			},
		},
		map[string]tftypes.Value{
			"names":         tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nameVals),
			"values":        tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
			"fail_on_error": failOnErrorVal,
		},
	)
}

func getSecretsDataSourceTestSchema() schema.Schema {
	d := &SecretsDataSource{}
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}

// runNamesListValidators runs the shared "names" validator cases against the given validators.
// The batch secrets data source and ephemeral resource declare identical validators, so both
// call this helper with the validators pulled off their respective schemas.
func runNamesListValidators(t *testing.T, validators []validator.List) {
	t.Helper()

	cases := []struct {
		name        string
		configValue types.List
		expectError bool
	}{
		{name: "happy path", configValue: namesList("data/a"), expectError: false},
		{name: "empty list", configValue: namesList(), expectError: true},
		{name: "exceeds max batch size", configValue: namesListN(conjurapi.MaxSecretsInSingleBatch + 1), expectError: true},
		{name: "empty string element", configValue: namesList("data/a", ""), expectError: true},
		{name: "whitespace-only element", configValue: namesList("data/a", " \t\n"), expectError: true},
		{name: "element with inner whitespace", configValue: namesList("data/my secret"), expectError: false},
		{name: "duplicate elements", configValue: namesList("data/a", "data/a"), expectError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hasError bool
			for _, v := range validators {
				resp := &validator.ListResponse{}
				v.ValidateList(context.Background(), validator.ListRequest{Path: path.Root("names"), ConfigValue: tc.configValue}, resp)
				if resp.Diagnostics.HasError() {
					hasError = true
				}
			}
			assert.Equal(t, tc.expectError, hasError)
		})
	}
}

// namesList builds a types.List of strings for validator testing.
func namesList(vals ...string) types.List {
	elems := make([]attr.Value, len(vals))
	for i, v := range vals {
		elems[i] = types.StringValue(v)
	}
	return types.ListValueMust(types.StringType, elems)
}

// namesListN builds a types.List with n distinct non-empty string elements.
func namesListN(n int) types.List {
	vals := make([]string, n)
	for i := range vals {
		vals[i] = fmt.Sprintf("data/secret-%d", i)
	}
	return namesList(vals...)
}
