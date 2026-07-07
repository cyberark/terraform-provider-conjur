package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestTrustDomainResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := NewTrustDomainResource()

	schemaRequest := resource.SchemaRequest{}
	schemaResponse := &resource.SchemaResponse{}

	r.Schema(ctx, schemaRequest, schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics had errors: %+v", schemaResponse.Diagnostics)
	}

	if diagnostics := schemaResponse.Schema.ValidateImplementation(ctx); diagnostics.HasError() {
		t.Fatalf("Schema validation failed: %+v", diagnostics)
	}
}
