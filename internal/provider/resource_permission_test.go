package provider

import (
	"context"
	"testing"

	"github.com/doodlesbykumbi/conjur-policy-go/pkg/conjurpolicy"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestConjurPermissionResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ds := NewConjurPermissionResource()

	schemaRequest := resource.SchemaRequest{}
	schemaResponse := &resource.SchemaResponse{}

	ds.Schema(ctx, schemaRequest, schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics had errors: %+v", schemaResponse.Diagnostics)
	}

	if diagnostics := schemaResponse.Schema.ValidateImplementation(ctx); diagnostics.HasError() {
		t.Fatalf("Schema validation failed: %+v", diagnostics)
	}
}

func TestConjurPermissionResource_generatePermissionPolicy(t *testing.T) {
	r := &ConjurPermissionResource{}

	t.Run("All permission fields provided", func(t *testing.T) {
		data := &ConjurPermissionResourceModel{
			Role: RoleModel{
				Name:   types.StringValue("my-role"),
				Kind:   types.StringValue("host"),
				Branch: types.StringValue("data/terraform/test"),
			},
			Resource: ResourceModel{
				Name:   types.StringValue("my-secret"),
				Kind:   types.StringValue("variable"),
				Branch: types.StringValue("data/terraform/dev/secrets"),
			},
			Privileges: types.ListValueMust(
				types.StringType,
				[]attr.Value{
					types.StringValue("execute"),
					types.StringValue("update"),
					types.StringValue("read"),
				},
			),
		}

		branch, permissionPolicy, err := r.generatePermissionPolicy(data)

		require.NoError(t, err)
		require.NotNil(t, permissionPolicy)

		expected := `- !permit
  role: !host test/my-role
  privileges: [execute, update, read]
  resource: !variable dev/secrets/my-secret
- !deny
  role: !host test/my-role
  privileges: [create]
  resource: !variable dev/secrets/my-secret
`
		require.Equal(t, expected, permissionPolicy)
		require.Equal(t, "data/terraform", branch)
	})
}

func TestConjurPermissionResource_generatePermissionDenyPolicy(t *testing.T) {
	r := &ConjurPermissionResource{}

	t.Run("All permission fields provided", func(t *testing.T) {
		data := &ConjurPermissionResourceModel{
			Role: RoleModel{
				Name:   types.StringValue("my-role"),
				Kind:   types.StringValue("host"),
				Branch: types.StringValue("data/terraform/test"),
			},
			Resource: ResourceModel{
				Name:   types.StringValue("my-secret"),
				Kind:   types.StringValue("variable"),
				Branch: types.StringValue("data/terraform/dev/secrets"),
			},
			Privileges: types.ListValueMust(
				types.StringType,
				[]attr.Value{
					types.StringValue("read"),
					types.StringValue("update"),
				},
			),
		}

		branch, permissionDenyPolicy, err := r.generatePermissionDenyPolicy(data)

		require.NoError(t, err)
		require.NotNil(t, permissionDenyPolicy)

		expected := `- !deny
  role: !host test/my-role
  privileges: [read, update]
  resource: !variable dev/secrets/my-secret
`
		require.Equal(t, expected, permissionDenyPolicy)
		require.Equal(t, "data/terraform", branch)
	})
}

func TestDerivePolicyContext(t *testing.T) {
	tests := []struct {
		name           string
		roleBranch     string
		roleName       string
		resourceBranch string
		resourceName   string
		wantBranch     string
		wantRoleID     string
		wantResourceID string
	}{
		{
			name:           "Partially shared policy paths",
			roleBranch:     "data/terraform/test",
			roleName:       "my-role",
			resourceBranch: "data/terraform/dev/secrets",
			resourceName:   "my-secret",
			wantBranch:     "data/terraform",
			wantRoleID:     "test/my-role",
			wantResourceID: "dev/secrets/my-secret",
		},
		{
			name:           "Same policy paths",
			roleBranch:     "data/terraform/test",
			roleName:       "my-role",
			resourceBranch: "data/terraform/test",
			resourceName:   "my-secret",
			wantBranch:     "data/terraform/test",
			wantRoleID:     "my-role",
			wantResourceID: "my-secret",
		},
		{
			name:           "Different policy paths",
			roleBranch:     "data/terraform/test",
			roleName:       "my-role",
			resourceBranch: "conjur/authn-jwt/test",
			resourceName:   "jwks-uri",
			wantBranch:     "",
			wantRoleID:     "data/terraform/test/my-role",
			wantResourceID: "conjur/authn-jwt/test/jwks-uri",
		},
		{
			name:           "One empty branch",
			roleBranch:     "",
			roleName:       "my-role",
			resourceBranch: "data/terraform/test",
			resourceName:   "my-secret",
			wantBranch:     "",
			wantRoleID:     "my-role",
			wantResourceID: "data/terraform/test/my-secret",
		},
		{
			name:           "Two empty branches",
			roleBranch:     "",
			roleName:       "my-role",
			resourceBranch: "",
			resourceName:   "my-secret",
			wantBranch:     "",
			wantRoleID:     "my-role",
			wantResourceID: "my-secret",
		},
		{
			name:           "Deeply nested branches",
			roleBranch:     "data/terraform/team1/project1",
			roleName:       "my-role",
			resourceBranch: "data/terraform/team1/project2/secrets",
			resourceName:   "my-secret",
			wantBranch:     "data/terraform/team1",
			wantRoleID:     "project1/my-role",
			wantResourceID: "project2/secrets/my-secret",
		},
		{
			name:           "Leading and trailing slashes",
			roleBranch:     "/data/terraform/test",
			roleName:       "my-role",
			resourceBranch: "/data/terraform/test/",
			resourceName:   "my-secret",
			wantBranch:     "data/terraform/test",
			wantRoleID:     "my-role",
			wantResourceID: "my-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue(tt.roleName),
					Branch: types.StringValue(tt.roleBranch),
				},
				Resource: ResourceModel{
					Name:   types.StringValue(tt.resourceName),
					Branch: types.StringValue(tt.resourceBranch),
				},
			}

			branch, roleID, resourceID := derivePolicyContext(data)

			assert.Equal(t, tt.wantBranch, branch)
			assert.Equal(t, tt.wantRoleID, roleID)
			assert.Equal(t, tt.wantResourceID, resourceID)
		})
	}
}

func TestSplitConjurID(t *testing.T) {
	tests := []struct {
		name       string
		fullID     string
		wantKind   string
		wantBranch string
		wantName   string
		wantErr    bool
	}{
		{
			name:       "Normal with branch",
			fullID:     "host/data/terraform/my-role",
			wantKind:   "host",
			wantBranch: "data/terraform",
			wantName:   "my-role",
			wantErr:    false,
		},
		{
			name:       "No branch",
			fullID:     "variable/my-secret",
			wantKind:   "variable",
			wantBranch: "",
			wantName:   "my-secret",
			wantErr:    false,
		},
		{
			name:    "Single segment (invalid)",
			fullID:  "invalid",
			wantErr: true,
		},
		{
			name:       "Leading slash",
			fullID:     "/host/data/terraform/my-role",
			wantKind:   "",
			wantBranch: "host/data/terraform",
			wantName:   "my-role",
			wantErr:    false,
		},
		{
			name:       "Trailing slash",
			fullID:     "host/data/terraform/my-role/",
			wantKind:   "host",
			wantBranch: "data/terraform/my-role",
			wantName:   "",
			wantErr:    false,
		},
		{
			name:       "Two segments only",
			fullID:     "host/my-role",
			wantKind:   "host",
			wantBranch: "",
			wantName:   "my-role",
			wantErr:    false,
		},
		{
			name:    "Empty string",
			fullID:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, branch, name, err := splitConjurID(tt.fullID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantKind, kind)
			assert.Equal(t, tt.wantBranch, branch)
			assert.Equal(t, tt.wantName, name)
		})
	}
}

// TestGeneratePermissionPolicy_YAMLInjection tests that user input cannot inject additional YAML statements
func TestGeneratePermissionPolicy_YAMLInjection(t *testing.T) {
	r := &ConjurPermissionResource{}

	testCases := []struct {
		name           string
		roleName       string
		roleBranch     string
		resourceName   string
		resourceBranch string
		description    string
	}{
		{
			name:           "newline injection in role name",
			roleName:       "role\n- !delete\n  record: !variable injected",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that newlines in role name don't create new statements",
		},
		{
			name:           "newline injection in resource name",
			roleName:       "role",
			roleBranch:     "data/test",
			resourceName:   "resource\n- !delete\n  record: !variable injected",
			resourceBranch: "data/test",
			description:    "Test that newlines in resource name don't create new statements",
		},
		{
			name:           "newline injection in role branch",
			roleName:       "role",
			roleBranch:     "data/test\n- !delete\n  record: !variable injected",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that newlines in role branch don't create new statements",
		},
		{
			name:           "newline injection in resource branch",
			roleName:       "role",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test\n- !delete\n  record: !variable injected",
			description:    "Test that newlines in resource branch don't create new statements",
		},
		{
			name:           "YAML tag injection in role name",
			roleName:       "role: !!str injected",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that YAML tags in role name are escaped",
		},
		{
			name:           "special characters in role name",
			roleName:       "role:with:colons|and|pipes",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that special characters in role name are handled",
		},
		{
			name:           "unicode in role name",
			roleName:       "role-测试-🚀",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that unicode characters in role name are handled",
		},
		{
			name:           "control characters in role name",
			roleName:       "role\x00\x01\x02value",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that control characters in role name are handled",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := &ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue(tc.roleName),
					Kind:   types.StringValue("host"),
					Branch: types.StringValue(tc.roleBranch),
				},
				Resource: ResourceModel{
					Name:   types.StringValue(tc.resourceName),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue(tc.resourceBranch),
				},
				Privileges: types.ListValueMust(
					types.StringType,
					[]attr.Value{
						types.StringValue("read"),
					},
				),
			}

			branch, policy, err := r.generatePermissionPolicy(data)
			require.NoError(t, err, "Policy generation should not fail for: %s", tc.description)
			require.NotEmpty(t, branch, "Branch should not be empty")

			// Verify the policy string is valid YAML by unmarshalling it back into the policy struct
			var policyStatements conjurpolicy.PolicyStatements
			err = yaml.Unmarshal([]byte(policy), &policyStatements)
			require.NoError(t, err, "Policy should be valid YAML and parseable into PolicyStatements for: %s", tc.description)

			// Verify we have exactly two statements (Permit and Deny), i.e. no injection has occurred
			assert.Len(t, policyStatements, 2, "Policy should contain exactly two statements (Permit and Deny). Policy: %s", policy)

			// Verify the first statement is a Permit statement
			permitStmt, ok := policyStatements[0].(conjurpolicy.Permit)
			require.True(t, ok, "First statement should be a Permit statement. Policy: %s", policy)

			// Verify role and resource IDs match input (after branch normalization)
			assert.Contains(t, permitStmt.Role.Id, tc.roleName,
				"Role ID should contain role name. Expected to contain: %q, Got: %q. Policy: %s",
				tc.roleName, permitStmt.Role.Id, policy)
			assert.Contains(t, permitStmt.Resources.Id, tc.resourceName,
				"Resource ID should contain resource name. Expected to contain: %q, Got: %q. Policy: %s",
				tc.resourceName, permitStmt.Resources.Id, policy)
		})
	}
}

// TestGeneratePermissionDenyPolicy_YAMLInjection tests that user input cannot inject additional YAML statements
func TestGeneratePermissionDenyPolicy_YAMLInjection(t *testing.T) {
	r := &ConjurPermissionResource{}

	testCases := []struct {
		name           string
		roleName       string
		roleBranch     string
		resourceName   string
		resourceBranch string
		description    string
	}{
		{
			name:           "newline injection in role name",
			roleName:       "role\n- !delete\n  record: !variable injected",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that newlines in role name don't create new statements",
		},
		{
			name:           "newline injection in resource name",
			roleName:       "role",
			roleBranch:     "data/test",
			resourceName:   "resource\n- !delete\n  record: !variable injected",
			resourceBranch: "data/test",
			description:    "Test that newlines in resource name don't create new statements",
		},
		{
			name:           "newline injection in role branch",
			roleName:       "role",
			roleBranch:     "data/test\n- !delete\n  record: !variable injected",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that newlines in role branch don't create new statements",
		},
		{
			name:           "newline injection in resource branch",
			roleName:       "role",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test\n- !delete\n  record: !variable injected",
			description:    "Test that newlines in resource branch don't create new statements",
		},
		{
			name:           "YAML tag injection in role name",
			roleName:       "role: !!str injected",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that YAML tags in role name are escaped",
		},
		{
			name:           "special characters in role name",
			roleName:       "role:with:colons|and|pipes",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that special characters in role name are handled",
		},
		{
			name:           "unicode in role name",
			roleName:       "role-测试-🚀",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that unicode characters in role name are handled",
		},
		{
			name:           "control characters in role name",
			roleName:       "role\x00\x01\x02value",
			roleBranch:     "data/test",
			resourceName:   "resource",
			resourceBranch: "data/test",
			description:    "Test that control characters in role name are handled",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := &ConjurPermissionResourceModel{
				Role: RoleModel{
					Name:   types.StringValue(tc.roleName),
					Kind:   types.StringValue("host"),
					Branch: types.StringValue(tc.roleBranch),
				},
				Resource: ResourceModel{
					Name:   types.StringValue(tc.resourceName),
					Kind:   types.StringValue("variable"),
					Branch: types.StringValue(tc.resourceBranch),
				},
				Privileges: types.ListValueMust(
					types.StringType,
					[]attr.Value{
						types.StringValue("read"),
					},
				),
			}

			branch, policy, err := r.generatePermissionDenyPolicy(data)
			require.NoError(t, err, "Policy generation should not fail for: %s", tc.description)
			require.NotEmpty(t, branch, "Branch should not be empty")

			// Verify the policy string is valid YAML by unmarshalling it back into the policy struct
			var policyStatements conjurpolicy.PolicyStatements
			err = yaml.Unmarshal([]byte(policy), &policyStatements)
			require.NoError(t, err, "Policy should be valid YAML and parseable into PolicyStatements for: %s", tc.description)

			// Verify we have exactly one statement (Deny), i.e. no injection has occurred
			assert.Len(t, policyStatements, 1, "Policy should contain exactly one statement (Deny). Policy: %s", policy)

			// Verify the statement is a Deny statement
			denyStmt, ok := policyStatements[0].(conjurpolicy.Deny)
			require.True(t, ok, "First statement should be a Deny statement. Policy: %s", policy)

			// Verify role and resource IDs match input (after branch normalization)
			assert.Contains(t, denyStmt.Role.Id, tc.roleName,
				"Role ID should contain role name. Expected to contain: %q, Got: %q. Policy: %s",
				tc.roleName, denyStmt.Role.Id, policy)
			assert.Contains(t, denyStmt.Resources.Id, tc.resourceName,
				"Resource ID should contain resource name. Expected to contain: %q, Got: %q. Policy: %s",
				tc.resourceName, denyStmt.Resources.Id, policy)
		})
	}
}
