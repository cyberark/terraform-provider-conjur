package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// applyPolicy applies a policy to Conjur using PATCH mode
func ApplyPolicy(client *conjurapi.Client, policy, branch string) error {
	policyResponse, err := client.LoadPolicy(conjurapi.PolicyModePatch, branch, strings.NewReader(policy))
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	// Log the policy response for debugging
	tflog.Debug(context.Background(), "Policy applied successfully", map[string]interface{}{
		"created_roles": policyResponse.CreatedRoles,
		"version":       policyResponse.Version,
	})

	return nil
}
