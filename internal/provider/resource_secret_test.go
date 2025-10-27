package provider

import (
	"context"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
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
	data := &ConjurSecretResourceModel{
		Name: types.StringValue("my-secret"),
	}

	policy, err := r.generateSecretDeletionPolicy(data)
	assert.NoError(t, err)
	assert.Equal(t, `- !delete
  record: !variable my-secret
`, policy)
}
