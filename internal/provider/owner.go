package provider

import (
	"fmt"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ownerFromObject extracts a *conjurapi.Owner from an "owner" nested attribute.
// It returns nil when the owner is null or unknown, and nil plus an error
// diagnostic when kind/id aren't strings, so a configured owner is never
// silently dropped. An empty block (owner = {}) is passed through, not treated
// as "no owner", so the blank kind is rejected downstream.
func ownerFromObject(obj types.Object) (*conjurapi.Owner, diag.Diagnostics) {
	var diags diag.Diagnostics
	if obj.IsNull() || obj.IsUnknown() {
		return nil, diags
	}
	kind, kindOK := obj.Attributes()["kind"].(types.String)
	id, idOK := obj.Attributes()["id"].(types.String)
	if !kindOK || !idOK {
		diags.AddAttributeError(path.Root("owner"), "Invalid Owner", fmt.Sprintf("Expected owner.kind and owner.id to be strings, got %T and %T.", obj.Attributes()["kind"], obj.Attributes()["id"]))
		return nil, diags
	}
	return &conjurapi.Owner{Kind: kind.ValueString(), Id: id.ValueString()}, diags
}

// ownerToObject is the inverse of ownerFromObject: it builds the "owner"
// nested attribute value from a *conjurapi.Owner (or its null representation,
// for owner == nil), for resources refreshing state from an API response.
func ownerToObject(owner *conjurapi.Owner) types.Object {
	if owner == nil {
		return types.ObjectNull(map[string]attr.Type{
			"kind": types.StringType,
			"id":   types.StringType,
		})
	}
	obj, _ := types.ObjectValue(
		map[string]attr.Type{
			"kind": types.StringType,
			"id":   types.StringType,
		},
		map[string]attr.Value{
			"kind": types.StringValue(owner.Kind),
			"id":   types.StringValue(owner.Id),
		},
	)
	return obj
}
