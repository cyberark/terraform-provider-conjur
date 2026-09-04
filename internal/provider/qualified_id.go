package provider

import (
	"fmt"

	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
)

// fullyQualifiedID returns "<account>:<kind>:<identifier>" for use with api.ClientV2 methods
// (RoleExists, CheckPermissionForRole, RoleMemberships, ...) that parse IDs by splitting on
// colons. The account must always be explicit: a colon inside identifier (e.g. a SPIFFE ID's
// "spiffe://") would otherwise be misread as the account/kind delimiter by conjur-api-go's
// unopinionatedParseID, which only ever treats the first two colons as delimiters.
func fullyQualifiedID(client api.ClientV2, kind, identifier string) string {
	return fmt.Sprintf("%s:%s:%s", client.GetConfig().Account, kind, identifier)
}
