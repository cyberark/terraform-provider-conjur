package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
