package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Create a global mutex to prevent concurrent policy updates
var policyMutex sync.Mutex

// ApplyPolicy applies a policy to Conjur using PATCH mode
func ApplyPolicy(client api.ClientV2, policy, branch string) error {
	policyMutex.Lock()
	defer policyMutex.Unlock()

	policyResponse, err := client.LoadPolicy(conjurapi.PolicyModePatch, branch, strings.NewReader(policy))
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	// Log the policy response for debugging
	tflog.Debug(context.Background(), "Policy applied successfully", map[string]any{
		"created_roles_count": len(policyResponse.CreatedRoles),
		"version":             policyResponse.Version,
	})

	return nil
}
