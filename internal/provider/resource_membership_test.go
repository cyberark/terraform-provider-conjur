package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestConjurMembershipResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ds := NewConjurMembershipResource()

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

func testGroupMemberConfig() string {
	return fmt.Sprintf(`
%s

resource "conjur_membership" "test" {
  group_id    = %q
  member_kind = %q
  member_id   = %q
}
`, providerApiConfig,
		os.Getenv("TF_CONJUR_GROUP_ID"),
		os.Getenv("TF_CONJUR_MEMBER_KIND"),
		os.Getenv("TF_CONJUR_MEMBER_ID"),
	)
}

func TestSplitGroupMemberID(t *testing.T) {
	t.Run("Valid id", func(t *testing.T) {
		id := "data/test/test-users:host:data/test/bob"
		group, kind, member, err := splitGroupMemberID(id)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if group != "data/test/test-users" {
			t.Fatalf("Unexpected group: %q", group)
		}
		if kind != "host" {
			t.Fatalf("Unexpected kind: %q", kind)
		}
		if member != "data/test/bob" {
			t.Fatalf("Unexpected member: %q", member)
		}
	})

	t.Run("Invalid ids", func(t *testing.T) {
		cases := []string{
			"", "only:two", "group", "group:user:id:extra",
			"::", ":user:id", "group::id", "group:user:",
		}
		for _, id := range cases {
			if _, _, _, err := splitGroupMemberID(id); err == nil {
				t.Fatalf("Expected error for id %q, got nil", id)
			}
		}
	})
}
