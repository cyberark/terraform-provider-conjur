package provider

import (
	"context"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/doodlesbykumbi/conjur-policy-go/pkg/conjurpolicy"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestConjurSecretResource_Schema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ds := NewConjurSecretResource()
	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	ds.Schema(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics had errors: %+v", resp.Diagnostics)
	}

	if diagnostics := resp.Schema.ValidateImplementation(ctx); diagnostics.HasError() {
		t.Fatalf("Schema validation failed: %+v", diagnostics)
	}
}

func TestBuildSecretPayload(t *testing.T) {
	r := &ConjurSecretResource{}

	// Permissions need []attr.Value for the List
	privs := []attr.Value{
		types.StringValue("read"),
		types.StringValue("write"),
	}

	model := &ConjurSecretResourceModel{
		Name:     types.StringValue("my-secret"),
		Branch:   types.StringValue("/my/branch"),
		MimeType: types.StringValue("text/plain"),
		Value:    types.StringValue("supersecret"),
		Permissions: []ConjurSecretPermission{
			{
				Subject: ConjurSecretSubject{
					Id:   types.StringValue("alice"),
					Kind: types.StringValue("user"),
				},
				Privileges: types.ListValueMust(types.StringType, privs),
			},
		},
		Owner: types.ObjectValueMust(map[string]attr.Type{
			"kind": types.StringType,
			"id":   types.StringType,
		}, map[string]attr.Value{
			"kind": types.StringValue("user"),
			"id":   types.StringValue("bob"),
		}),
		Annotations: map[string]string{"env": "dev"},
	}

	secret, err := r.buildSecretPayload(model)
	assert.NoError(t, err)

	assert.Equal(t, "my-secret", secret.Name)
	assert.Equal(t, "/my/branch", secret.Branch)
	assert.Equal(t, "text/plain", secret.MimeType)
	assert.Equal(t, "supersecret", secret.Value)

	// Permissions
	assert.Len(t, secret.Permissions, 1)
	assert.Equal(t, "alice", secret.Permissions[0].Subject.Id)
	assert.Equal(t, "user", secret.Permissions[0].Subject.Kind)
	assert.Equal(t, []string{"read", "write"}, secret.Permissions[0].Privileges)

	// Owner
	assert.NotNil(t, secret.Owner)
	assert.Equal(t, "bob", secret.Owner.Id)
	assert.Equal(t, "user", secret.Owner.Kind)

	// Annotations
	assert.Equal(t, map[string]string{"env": "dev"}, secret.Annotations)
}

func TestParseSecretResponse(t *testing.T) {
	r := &ConjurSecretResource{}
	data := &ConjurSecretResourceModel{}

	secretResp := conjurapi.StaticSecretResponse{
		StaticSecret: conjurapi.StaticSecret{
			Name:     "my-secret",
			Branch:   "/branch",
			MimeType: "text/plain",
			Owner: &conjurapi.Owner{
				Kind: "user",
				Id:   "owner1",
			},
			Annotations: map[string]string{
				"env": "prod",
			},
		},
	}

	permResp := conjurapi.PermissionResponse{
		Permission: []conjurapi.Permission{
			{
				Subject: conjurapi.Subject{
					Id:   "user1",
					Kind: "user",
				},
				Privileges: []string{"read"},
			},
		},
	}

	err := r.parseSecretResponse(secretResp, permResp, data)
	assert.NoError(t, err)
	assert.Equal(t, "my-secret", data.Name.ValueString())
	assert.Equal(t, "/branch", data.Branch.ValueString())
	assert.Equal(t, "text/plain", data.MimeType.ValueString())
	assert.Equal(t, "user1", data.Permissions[0].Subject.Id.ValueString())
	assert.Equal(t, "user", data.Permissions[0].Subject.Kind.ValueString())
	privs := data.Permissions[0].Privileges.Elements()
	var privStrs []string
	for _, p := range privs {
		privStrs = append(privStrs, p.(types.String).ValueString())
	}

	assert.ElementsMatch(t, []string{"read"}, privStrs)
	assert.Equal(t, "user", data.Owner.Attributes()["kind"].(types.String).ValueString())
	assert.Equal(t, "owner1", data.Owner.Attributes()["id"].(types.String).ValueString())
	assert.Equal(t, map[string]string{"env": "prod"}, data.Annotations)
}

func TestGenerateSecretDeletionPolicy(t *testing.T) {
	r := &ConjurSecretResource{}

	testCases := []struct {
		name        string
		secretName  string
		description string
	}{
		{
			name:        "happy path",
			secretName:  "my-secret",
			description: "Test that happy path works",
		},
		{
			name:        "colon character",
			secretName:  "secret:value",
			description: "Test that colon characters are properly escaped",
		},
		{
			name:        "pipe character",
			secretName:  "secret|value",
			description: "Test that pipe characters don't create multiline blocks",
		},
		{
			name:        "greater than character",
			secretName:  "secret>value",
			description: "Test that greater than characters don't create folded blocks",
		},
		{
			name:        "ampersand and asterisk",
			secretName:  "secret&*value",
			description: "Test that anchor and alias characters are escaped",
		},
		{
			name:        "hash character",
			secretName:  "secret#value",
			description: "Test that hash characters don't create comments",
		},
		{
			name:        "exclamation mark",
			secretName:  "secret!value",
			description: "Test that exclamation marks don't interfere with YAML tags",
		},
		{
			name:        "at symbol",
			secretName:  "secret@value",
			description: "Test that at symbols are properly escaped",
		},
		{
			name:        "backtick",
			secretName:  "secret`value",
			description: "Test that backticks are properly escaped",
		},
		{
			name:        "single quotes",
			secretName:  "secret'value",
			description: "Test that single quotes are properly escaped",
		},
		{
			name:        "double quotes",
			secretName:  `secret"value`,
			description: "Test that double quotes are properly escaped",
		},
		{
			name:        "newline character",
			secretName:  "secret\nvalue",
			description: "Test that newlines don't break YAML structure",
		},
		{
			name:        "carriage return",
			secretName:  "secret\rvalue",
			description: "Test that carriage returns are handled",
		},
		{
			name:        "tab character",
			secretName:  "secret\tvalue",
			description: "Test that tabs are properly escaped",
		},
		{
			name:        "attempted YAML tag injection",
			secretName:  "secret\n- !delete\n  record: !variable injected",
			description: "Test that newlines don't allow injecting additional YAML statements",
		},
		{
			name:        "attempted YAML anchor injection",
			secretName:  "secret&anchor *alias",
			description: "Test that anchors and aliases don't allow injection",
		},
		{
			name:        "attempted comment injection",
			secretName:  "secret # injected comment",
			description: "Test that hash characters don't create comments",
		},
		{
			name:        "multiline block attempt",
			secretName:  "secret\n|multiline\nblock",
			description: "Test that multiline block syntax is escaped",
		},
		{
			name:        "folded block attempt",
			secretName:  "secret\n>folded\nblock",
			description: "Test that folded block syntax is escaped",
		},
		{
			name:        "unicode characters",
			secretName:  "secret-测试-🚀",
			description: "Test that unicode characters are handled",
		},
		{
			name:        "control characters",
			secretName:  "secret\x00\x01\x02value",
			description: "Test that control characters are handled",
		},
		{
			name:        "only special characters",
			secretName:  ":|>&*#!@`'\"",
			description: "Test string with only special YAML characters",
		},
		{
			name:        "YAML document separator attempt",
			secretName:  "secret---value",
			description: "Test that document separators don't break structure",
		},
		{
			name:        "YAML document end attempt",
			secretName:  "secret...value",
			description: "Test that document end markers don't break structure",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := &ConjurSecretResourceModel{
				Name: types.StringValue(tc.secretName),
			}

			policy, err := r.generateSecretDeletionPolicy(data)
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

			// Verify the variable name in policy matches the input exactly
			assert.Equal(t, tc.secretName, deleteStmt.Record.Id,
				"Variable name should match input exactly. Expected: %q, Got: %q. Policy: %s",
				tc.secretName, deleteStmt.Record.Id, policy)

			// Verify the record kind is Variable
			assert.Equal(t, conjurpolicy.KindVariable, deleteStmt.Record.Kind,
				"Record kind should be Variable")

			// Additional check: verify the policy text contains the expected structure
			assert.Contains(t, policy, "!delete", "Policy should contain delete statement")
			assert.Contains(t, policy, "!variable", "Policy should contain variable reference")
		})
	}
}
