package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	tf_resource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
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

func TestAPIGroupMemberResource_CreateDestroy(t *testing.T) {
	tf_resource.Test(t, tf_resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tf_resource.TestStep{
			{
				Config: testGroupMemberConfig(),
				Check: tf_resource.ComposeTestCheckFunc(
					tf_resource.TestCheckResourceAttr(
						"conjur_membership.test",
						"id",
						os.Getenv("TF_CONJUR_GROUP_ID")+groupMemberIDSeparator+os.Getenv("TF_CONJUR_MEMBER_KIND")+groupMemberIDSeparator+os.Getenv("TF_CONJUR_MEMBER_ID"),
					),
				),
			},
			{
				Config:  testGroupMemberConfig(),
				Destroy: true,
			},
		},
	})
}

func TestValidateKind(t *testing.T) {
	t.Run("Valid kinds", func(t *testing.T) {
		valid := []string{"user", "host", "group"}
		for _, kind := range valid {
			if err := validateKind(kind); err != nil {
				t.Fatalf("Expected no error for kind %q, got %v", kind, err)
			}
		}
	})

	t.Run("Invalid kinds", func(t *testing.T) {
		invalid := []string{
			"", "User", "service", " group", "user,host",
		}
		for _, kind := range invalid {
			if err := validateKind(kind); err == nil {
				t.Fatalf("Expected error for kind %q, got nil", kind)
			}
		}
	})
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
