package provider

import (
	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ownerFromObject safely extracts a *conjurapi.Owner from an "owner" nested
// attribute, or nil when it's null, unknown (the block was omitted from
// config entirely), or its attributes aren't the expected type - this is the
// single source of truth for that extraction so callers don't each repeat an
// unchecked type assertion that would panic on an unexpected attribute type.
// An empty-but-present block (owner = {}) is deliberately not "no owner":
// it's passed through so conjurpolicy.KindString rejects the blank kind in
// generateGroupPolicy, matching conjur_group's pre-V2 validation of an
// explicit but incomplete owner. Used directly by the policy-YAML backends
// that model owner as *conjurapi.Owner (conjur_group and
// conjur_policy_branch); conjur_authenticator remaps its two fields into its
// own conjurapi.AuthOwner, since the V2 Authenticator model uses that type
// instead.
func ownerFromObject(obj types.Object) *conjurapi.Owner {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	kind, kindOK := obj.Attributes()["kind"].(types.String)
	id, idOK := obj.Attributes()["id"].(types.String)
	if !kindOK || !idOK {
		return nil
	}
	return &conjurapi.Owner{Kind: kind.ValueString(), Id: id.ValueString()}
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
