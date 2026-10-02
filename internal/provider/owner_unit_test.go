package provider

import (
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOwnerFromObject(t *testing.T) {
	t.Parallel()

	ownerAttrTypes := map[string]attr.Type{"kind": types.StringType, "id": types.StringType}

	t.Run("null", func(t *testing.T) {
		t.Parallel()
		owner, diags := ownerFromObject(types.ObjectNull(ownerAttrTypes))
		assert.Nil(t, owner)
		assert.False(t, diags.HasError())
	})

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		owner, diags := ownerFromObject(types.ObjectUnknown(ownerAttrTypes))
		assert.Nil(t, owner)
		assert.False(t, diags.HasError())
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		obj, d := types.ObjectValue(ownerAttrTypes, map[string]attr.Value{"kind": types.StringValue("group"), "id": types.StringValue("admins")})
		require.False(t, d.HasError())
		owner, diags := ownerFromObject(obj)
		assert.False(t, diags.HasError())
		assert.Equal(t, &conjurapi.Owner{Kind: "group", Id: "admins"}, owner)
	})

	t.Run("type mismatch", func(t *testing.T) {
		t.Parallel()
		obj, d := types.ObjectValue(map[string]attr.Type{"kind": types.StringType, "id": types.Int64Type}, map[string]attr.Value{"kind": types.StringValue("group"), "id": types.Int64Value(1)})
		require.False(t, d.HasError())
		owner, diags := ownerFromObject(obj)
		assert.Nil(t, owner)
		require.True(t, diags.HasError())
		assert.Equal(t, "Invalid Owner", diags.Errors()[0].Summary())
	})
}
