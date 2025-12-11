package provider

import (
	"context"
	"testing"

	"github.com/doodlesbykumbi/conjur-policy-go/pkg/conjurpolicy"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestConjurGroupResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ds := NewConjurGroupResource()

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

func TestConjurGroupResource_generateGroupPolicy(t *testing.T) {
	r := &ConjurGroupResource{}

	t.Run("Minimum group fields provided", func(t *testing.T) {
		data := &ConjurGroupResourceModel{
			Name:        types.StringValue("test-group"),
			Branch:      types.StringValue("data"),
			Owner:       nil,
			Annotations: nil,
		}

		groupPolicy, err := r.generateGroupPolicy(data)

		require.NoError(t, err)
		require.NotNil(t, groupPolicy)
		assert.Contains(t, groupPolicy, "!group")
		assert.Contains(t, groupPolicy, "id: test-group")
	})

	t.Run("All group fields provided", func(t *testing.T) {
		data := &ConjurGroupResourceModel{
			Name:   types.StringValue("test-group"),
			Branch: types.StringValue("data/production"),
			Owner: &ConjurOwnerModel{
				Kind: types.StringValue("group"),
				ID:   types.StringValue("jenkins-admins"),
			},
			Annotations: map[string]string{
				"environment": "production",
				"team":        "security",
			},
		}

		groupPolicy, err := r.generateGroupPolicy(data)

		require.NoError(t, err)
		require.NotNil(t, groupPolicy)

		assert.Contains(t, groupPolicy, "!group")
		assert.Contains(t, groupPolicy, "id: test-group")
		assert.Contains(t, groupPolicy, "owner: !group jenkins-admins")
		assert.Contains(t, groupPolicy, "annotations:")
		assert.Contains(t, groupPolicy, "environment: production")
		assert.Contains(t, groupPolicy, "team: security")
	})
}

func TestConjurGroupResource_generateGroupDeletionPolicy(t *testing.T) {
	r := &ConjurGroupResource{}

	t.Run("Generate deletion policy", func(t *testing.T) {
		data := &ConjurGroupResourceModel{
			Name:   types.StringValue("test-group"),
			Branch: types.StringValue("data"),
		}

		deletionPolicy, err := r.generateGroupDeletionPolicy(data)
		require.NoError(t, err)

		require.NotNil(t, deletionPolicy)
		assert.Contains(t, deletionPolicy, "!delete")
		assert.Contains(t, deletionPolicy, "record: !group test-group")
	})
}

// TestGenerateGroupPolicy_YAMLInjection tests that user input cannot inject additional YAML statements
func TestGenerateGroupPolicy_YAMLInjection(t *testing.T) {
	r := &ConjurGroupResource{}

	testCases := []struct {
		name        string
		groupName   string
		ownerKind   string
		ownerID     string
		annotations map[string]string
		description string
	}{
		{
			name:        "newline injection in name",
			groupName:   "group\n- !delete\n  record: !variable injected",
			description: "Test that newlines in group name don't create new statements",
		},
		{
			name:        "YAML tag injection in name",
			groupName:   "group: !!str injected",
			description: "Test that YAML tags in group name are escaped",
		},
		{
			name:        "multiline block injection in name",
			groupName:   "group\n  - !delete\n    record: !variable injected",
			description: "Test that multiline blocks in group name don't create new statements",
		},
		{
			name:        "newline injection in owner id",
			groupName:   "test-group",
			ownerKind:   "group",
			ownerID:     "owner\n- !delete\n  record: !variable injected",
			description: "Test that newlines in owner id don't create new statements",
		},
		{
			name:      "newline injection in annotation key",
			groupName: "test-group",
			annotations: map[string]string{
				"key\n- !delete\n  record: !variable injected": "value",
			},
			description: "Test that newlines in annotation keys don't create new statements",
		},
		{
			name:      "newline injection in annotation value",
			groupName: "test-group",
			annotations: map[string]string{
				"key": "value\n- !delete\n  record: !variable injected",
			},
			description: "Test that newlines in annotation values don't create new statements",
		},
		{
			name:        "special characters in name",
			groupName:   "group:with:colons|and|pipes",
			description: "Test that special characters are handled",
		},
		{
			name:        "unicode in name",
			groupName:   "group-测试-🚀",
			description: "Test that unicode characters are handled",
		},
		{
			name:        "control characters in name",
			groupName:   "group\x00\x01\x02value",
			description: "Test that control characters are handled",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := &ConjurGroupResourceModel{
				Name:   types.StringValue(tc.groupName),
				Branch: types.StringValue("data"),
			}

			if tc.ownerKind != "" || tc.ownerID != "" {
				data.Owner = &ConjurOwnerModel{
					Kind: types.StringValue(tc.ownerKind),
					ID:   types.StringValue(tc.ownerID),
				}
			}

			if tc.annotations != nil {
				data.Annotations = tc.annotations
			}

			policy, err := r.generateGroupPolicy(data)
			require.NoError(t, err, "Policy generation should not fail for: %s", tc.description)

			// Verify the policy string is valid YAML by unmarshalling it back into the policy struct
			var policyStatements conjurpolicy.PolicyStatements
			err = yaml.Unmarshal([]byte(policy), &policyStatements)
			require.NoError(t, err, "Policy should be valid YAML and parseable into PolicyStatements for: %s", tc.description)

			// Verify we have exactly one statement in the parsed YAML, i.e. no injection has occurred
			assert.Len(t, policyStatements, 1, "Policy should contain exactly one statement. Policy: %s", policy)

			// Verify the statement is a Group statement
			groupStmt, ok := policyStatements[0].(conjurpolicy.Group)
			require.True(t, ok, "First statement should be a Group statement. Policy: %s", policy)

			// Verify the group name in policy matches the input exactly
			assert.Equal(t, tc.groupName, groupStmt.Id,
				"Group name should match input exactly. Expected: %q, Got: %q. Policy: %s",
				tc.groupName, groupStmt.Id, policy)
		})
	}
}

// TestGenerateGroupDeletionPolicy_YAMLInjection tests that user input cannot inject additional YAML statements
func TestGenerateGroupDeletionPolicy_YAMLInjection(t *testing.T) {
	r := &ConjurGroupResource{}

	testCases := []struct {
		name        string
		groupName   string
		description string
	}{
		{
			name:        "newline injection",
			groupName:   "group\n- !delete\n  record: !variable injected",
			description: "Test that newlines in group name don't create new statements",
		},
		{
			name:        "YAML tag injection",
			groupName:   "group: !!str injected",
			description: "Test that YAML tags in group name are escaped",
		},
		{
			name:        "multiline block injection",
			groupName:   "group\n  - !delete\n    record: !variable injected",
			description: "Test that multiline blocks in group name don't create new statements",
		},
		{
			name:        "special characters",
			groupName:   "group:with:colons|and|pipes",
			description: "Test that special characters are handled",
		},
		{
			name:        "unicode",
			groupName:   "group-测试-🚀",
			description: "Test that unicode characters are handled",
		},
		{
			name:        "control characters",
			groupName:   "group\x00\x01\x02value",
			description: "Test that control characters are handled",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := &ConjurGroupResourceModel{
				Name:   types.StringValue(tc.groupName),
				Branch: types.StringValue("data"),
			}

			policy, err := r.generateGroupDeletionPolicy(data)
			require.NoError(t, err, "Policy generation should not fail for: %s", tc.description)

			// Verify the policy string is valid YAML by unmarshalling it back into the policy struct
			var policyStatements conjurpolicy.PolicyStatements
			err = yaml.Unmarshal([]byte(policy), &policyStatements)
			require.NoError(t, err, "Policy should be valid YAML and parseable into PolicyStatements for: %s", tc.description)

			// Verify we have exactly one statement in the parsed YAML, i.e. no injection has occurred
			assert.Len(t, policyStatements, 1, "Policy should contain exactly one statement. Policy: %s", policy)

			// Verify the statement is a Delete statement
			deleteStmt, ok := policyStatements[0].(conjurpolicy.Delete)
			require.True(t, ok, "First statement should be a Delete statement. Policy: %s", policy)

			// Verify the group name in policy matches the input exactly
			assert.Equal(t, tc.groupName, deleteStmt.Record.Id,
				"Group name should match input exactly. Expected: %q, Got: %q. Policy: %s",
				tc.groupName, deleteStmt.Record.Id, policy)

			// Verify the record kind is Group
			assert.Equal(t, conjurpolicy.KindGroup, deleteStmt.Record.Kind,
				"Record kind should be Group")
		})
	}
}
