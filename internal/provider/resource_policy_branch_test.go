package provider

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func testAccPreCheck(t *testing.T) {
	req := []string{
		"CONJUR_APPLIANCE_URL",
		"CONJUR_ACCOUNT",
		"CONJUR_AUTHN_LOGIN",
		"CONJUR_AUTHN_API_KEY",
		"CONJUR_TEST_PARENT_BRANCH",
	}
	for _, k := range req {
		if v := os.Getenv(k); v == "" {
			t.Fatalf("%s must be set for acceptance tests", k)
		}
	}
}

func randSuffix(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func TestAccPolicyBranch_basic(t *testing.T) {
	t.Parallel()
	testAccPreCheck(t)

	parent := os.Getenv("CONJUR_TEST_PARENT_BRANCH")
	name := fmt.Sprintf("acc-%s", randSuffix(4))

	resourceName := "conjur_policy_branch.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyBranchConfig(parent, name, map[string]string{
					"acc": "true",
				}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "branch", parent),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "annotations.acc", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "full_id"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    importID(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "full_id",
			},
			{
				Config: testAccPolicyBranchConfig(parent, name, map[string]string{
					"acc": "true",
					"env": "dev",
				}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "annotations.acc", "true"),
					resource.TestCheckResourceAttr(resourceName, "annotations.env", "dev"),
				),
			},
			{
				Config: testAccPolicyBranchConfig(parent, name, map[string]string{
					"acc": "cleanup",
					"env": "dev",
				}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "annotations.acc", "cleanup"),
					resource.TestCheckResourceAttr(resourceName, "annotations.env", "dev"),
				),
			},
		},
	})
}

func testAccPolicyBranchConfig(parent, name string, ann map[string]string) string {
	anns := ""
	for k, v := range ann {
		anns += fmt.Sprintf("%q = %q\n", k, v)
	}
	return fmt.Sprintf(`
provider "conjur" {}

resource "conjur_policy_branch" "test" {
  branch = %q
  name   = %q

  annotations = {
    %s
  }
}
`, parent, name, anns)
}

func importID(resName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resName]
		if !ok {
			return "", fmt.Errorf("resource not found: %s", resName)
		}
		parent := rs.Primary.Attributes["branch"]
		name := rs.Primary.Attributes["name"]
		return fmt.Sprintf("%s/%s", parent, name), nil
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct {
		name     string
		parent   string
		leaf     string
		expected string
	}{
		{
			name:     "normal case",
			parent:   "apps/backend",
			leaf:     "staging",
			expected: "apps/backend/staging",
		},
		{
			name:     "empty parent",
			parent:   "",
			leaf:     "root",
			expected: "root",
		},
		{
			name:     "parent with trailing slash",
			parent:   "apps/",
			leaf:     "frontend",
			expected: "apps/frontend",
		},
		{
			name:     "leaf with leading slash",
			parent:   "apps",
			leaf:     "/frontend",
			expected: "apps/frontend",
		},
		{
			name:     "both with slashes",
			parent:   "/apps/backend/",
			leaf:     "/staging/",
			expected: "apps/backend/staging",
		},
		{
			name:     "only slashes",
			parent:   "/",
			leaf:     "/",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := joinPath(tt.parent, tt.leaf)
			if result != tt.expected {
				t.Errorf("joinPath(%q, %q) = %q, want %q", tt.parent, tt.leaf, result, tt.expected)
			}
		})
	}
}

func TestSplitParentAndName(t *testing.T) {
	tests := []struct {
		name           string
		id             string
		expectedParent string
		expectedName   string
	}{
		{
			name:           "normal path",
			id:             "apps/backend/staging",
			expectedParent: "apps/backend",
			expectedName:   "staging",
		},
		{
			name:           "single level",
			id:             "root",
			expectedParent: "",
			expectedName:   "root",
		},
		{
			name:           "two levels",
			id:             "apps/backend",
			expectedParent: "apps",
			expectedName:   "backend",
		},
		{
			name:           "with leading/trailing slashes",
			id:             "/apps/backend/staging/",
			expectedParent: "apps/backend",
			expectedName:   "staging",
		},
		{
			name:           "empty string",
			id:             "",
			expectedParent: "",
			expectedName:   "",
		},
		{
			name:           "only slash",
			id:             "/",
			expectedParent: "",
			expectedName:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent, name := splitParentAndName(tt.id)
			if parent != tt.expectedParent || name != tt.expectedName {
				t.Errorf("splitParentAndName(%q) = (%q, %q), want (%q, %q)",
					tt.id, parent, name, tt.expectedParent, tt.expectedName)
			}
		})
	}
}
