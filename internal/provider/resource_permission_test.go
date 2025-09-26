package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
