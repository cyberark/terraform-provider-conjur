package provider

import (
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/stretchr/testify/assert"
)

func TestFullyQualifiedID(t *testing.T) {
	tests := []struct {
		name       string
		account    string
		kind       string
		identifier string
		expected   string
	}{
		{
			name:       "simple host identifier",
			account:    "conjur",
			kind:       "host",
			identifier: "data/test-host",
			expected:   "conjur:host:data/test-host",
		},
		{
			name:       "identifier containing its own colon (e.g. a SPIFFE ID)",
			account:    "conjur",
			kind:       "host",
			identifier: "data/swa/trust-domains/prod.example.com/workloads/spiffe://prod.example.com/ns/myapp",
			expected:   "conjur:host:data/swa/trust-domains/prod.example.com/workloads/spiffe://prod.example.com/ns/myapp",
		},
		{
			name:       "different account and kind",
			account:    "myorg",
			kind:       "group",
			identifier: "data/admins",
			expected:   "myorg:group:data/admins",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			mockV2.On("GetConfig").Return(conjurapi.Config{Account: tt.account})

			result := fullyQualifiedID(mockV2, tt.kind, tt.identifier)

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBranchQualifiedID(t *testing.T) {
	tests := []struct {
		name     string
		branch   string
		id       string
		expected string
	}{
		{
			name:     "simple branch and name",
			branch:   "data",
			id:       "test-host",
			expected: "data/test-host",
		},
		{
			name:     "nested branch",
			branch:   "data/production/servers",
			id:       "server-01",
			expected: "data/production/servers/server-01",
		},
		{
			name:     "name containing its own slashes (e.g. a SPIFFE ID)",
			branch:   "data/swa/trust-domains/prod.example.com/workloads",
			id:       "spiffe://prod.example.com/ns/myapp/sa/myapp",
			expected: "data/swa/trust-domains/prod.example.com/workloads/spiffe://prod.example.com/ns/myapp/sa/myapp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := branchQualifiedID(tt.branch, tt.id)

			assert.Equal(t, tt.expected, result)
		})
	}
}
