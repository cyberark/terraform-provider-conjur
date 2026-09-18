package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
)

func TestEphemeralSecretsResourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaRequest := ephemeral.SchemaRequest{}
	schemaResponse := &ephemeral.SchemaResponse{}

	// Instantiate the ephemeral.EphemeralResource and call its Schema method
	NewEphemeralSecretsResource().Schema(ctx, schemaRequest, schemaResponse)

	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema method diagnostics: %+v", schemaResponse.Diagnostics)
	}

	// Validate the schema
	diagnostics := schemaResponse.Schema.ValidateImplementation(ctx)

	if diagnostics.HasError() {
		t.Fatalf("Schema validation diagnostics: %+v", diagnostics)
	}

	// The values attribute holds secret values and must remain Sensitive
	if !schemaResponse.Schema.Attributes["values"].IsSensitive() {
		t.Errorf("expected \"values\" attribute to be Sensitive, but it was not")
	}
}
