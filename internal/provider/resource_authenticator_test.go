package provider

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConjurAuthenticatorResource_Schema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ds := NewConjurAuthenticatorResource()

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

func TestConjurAuthenticatorResource_buildAuthenticatorPayload(t *testing.T) {
	r := &ConjurAuthenticatorResource{}

	t.Run("Minimum authenticator fields", func(t *testing.T) {
		data := &ConjurAuthenticatorResourceModel{
			Type:        types.StringValue("jwt"),
			Name:        types.StringValue("test-auth"),
			Subtype:     types.StringNull(),
			Enabled:     types.BoolNull(),
			Owner:       types.ObjectNull(map[string]attr.Type{}),
			Data:        nil,
			Annotations: nil,
		}

		result, err := r.buildAuthenticatorPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "jwt", result.Type)
		assert.Equal(t, "test-auth", result.Name)
		assert.Nil(t, result.Subtype)
		assert.Nil(t, result.Enabled)
		assert.Nil(t, result.Owner)
		assert.Nil(t, result.Data)
		assert.Nil(t, result.Annotations)
	})

	t.Run("All authenticator fields", func(t *testing.T) {
		enabled := true
		subtype := "github"
		ownerAttrs := map[string]attr.Value{
			"kind": types.StringValue("group"),
			"id":   types.StringValue("admin-group"),
		}

		data := &ConjurAuthenticatorResourceModel{
			Type:    types.StringValue("jwt"),
			Name:    types.StringValue("test-auth"),
			Subtype: types.StringValue("github"),
			Enabled: types.BoolValue(true),
			Owner: types.ObjectValueMust(map[string]attr.Type{
				"kind": types.StringType,
				"id":   types.StringType,
			}, ownerAttrs),
			Data: &ConjurAuthenticatorDataModel{
				Audience:   types.StringValue("test-audience"),
				JwksURI:    types.StringValue("https://example.com/jwks"),
				Issuer:     types.StringValue("test-issuer"),
				CACert:     types.StringValue("-----BEGIN CERTIFICATE-----"),
				PublicKeys: types.StringValue(`{"key1": "value1", "key2": "value2"}`),
				Identity: &ConjurAuthenticatorIdentityModel{
					IdentityPath:     types.StringValue("/identity/path"),
					TokenAppProperty: types.StringValue("app_property"),
					ClaimAliases: map[string]string{
						"sub": "subject",
						"aud": "audience",
					},
					EnforcedClaims: []string{"sub", "aud", "exp"},
				},
			},
			Annotations: map[string]string{
				"environment": "production",
				"team":        "security",
			},
		}

		result, err := r.buildAuthenticatorPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "jwt", result.Type)
		assert.Equal(t, "test-auth", result.Name)
		assert.Equal(t, subtype, *result.Subtype)
		assert.Equal(t, enabled, *result.Enabled)

		// Check Owner
		require.NotNil(t, result.Owner)
		assert.Equal(t, "group", result.Owner.Kind)
		assert.Equal(t, "admin-group", result.Owner.ID)

		// Check Data
		require.NotNil(t, result.Data)
		assert.Equal(t, "test-audience", result.Data["audience"])
		assert.Equal(t, "https://example.com/jwks", result.Data["jwks_uri"])
		assert.Equal(t, "test-issuer", result.Data["issuer"])
		assert.Equal(t, "-----BEGIN CERTIFICATE-----", result.Data["ca_cert"])

		// Check PublicKeys JSON unmarshaling
		publicKeysObj := result.Data["public_keys"]
		assert.NotNil(t, publicKeysObj)
		publicKeysMap, ok := publicKeysObj.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "value1", publicKeysMap["key1"])
		assert.Equal(t, "value2", publicKeysMap["key2"])

		// Check Identity
		identityObj, ok := result.Data["identity"]
		require.True(t, ok)
		identity, ok := identityObj.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "/identity/path", identity["identity_path"])
		assert.Equal(t, "app_property", identity["token_app_property"])

		claimAliases, ok := identity["claim_aliases"].(map[string]string)
		require.True(t, ok)
		assert.Equal(t, "subject", claimAliases["sub"])
		assert.Equal(t, "audience", claimAliases["aud"])

		enforcedClaims, ok := identity["enforced_claims"].([]string)
		require.True(t, ok)
		assert.Contains(t, enforcedClaims, "sub")
		assert.Contains(t, enforcedClaims, "aud")
		assert.Contains(t, enforcedClaims, "exp")

		// Check Annotations
		assert.Len(t, result.Annotations, 2)
		assert.Equal(t, "production", result.Annotations["environment"])
		assert.Equal(t, "security", result.Annotations["team"])
	})

	t.Run("Unknown fields omitted", func(t *testing.T) {
		data := &ConjurAuthenticatorResourceModel{
			Type:        types.StringValue("jwt"),
			Name:        types.StringValue("test-auth"),
			Subtype:     types.StringUnknown(),
			Enabled:     types.BoolUnknown(),
			Owner:       types.ObjectNull(map[string]attr.Type{}),
			Data:        nil,
			Annotations: nil,
		}

		result, err := r.buildAuthenticatorPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Nil(t, result.Subtype)
		assert.Nil(t, result.Enabled)
	})

	t.Run("Invalid public keys", func(t *testing.T) {
		data := &ConjurAuthenticatorResourceModel{
			Type: types.StringValue("jwt"),
			Name: types.StringValue("test-auth"),
			Data: &ConjurAuthenticatorDataModel{
				PublicKeys: types.StringValue("invalid-json"),
			},
		}

		result, err := r.buildAuthenticatorPayload(data)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid JSON in public_keys")
	})

	t.Run("Partial authenticator data", func(t *testing.T) {
		data := &ConjurAuthenticatorResourceModel{
			Type: types.StringValue("jwt"),
			Name: types.StringValue("test-auth"),
			Data: &ConjurAuthenticatorDataModel{
				Audience:   types.StringValue("test-audience"),
				JwksURI:    types.StringNull(),
				Issuer:     types.StringValue("test-issuer"),
				CACert:     types.StringNull(),
				PublicKeys: types.StringNull(),
				Identity:   nil,
			},
		}

		result, err := r.buildAuthenticatorPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, result)
		require.NotNil(t, result.Data)
		assert.Equal(t, "test-audience", result.Data["audience"])
		assert.Equal(t, "test-issuer", result.Data["issuer"])
		assert.NotContains(t, result.Data, "jwks_uri")
		assert.NotContains(t, result.Data, "ca_cert")
		assert.NotContains(t, result.Data, "public_keys")
		assert.NotContains(t, result.Data, "identity")
	})

	t.Run("EmptyIdentityFields", func(t *testing.T) {
		data := &ConjurAuthenticatorResourceModel{
			Type: types.StringValue("jwt"),
			Name: types.StringValue("test-auth"),
			Data: &ConjurAuthenticatorDataModel{
				Identity: &ConjurAuthenticatorIdentityModel{
					IdentityPath:     types.StringNull(),
					TokenAppProperty: types.StringNull(),
					ClaimAliases:     map[string]string{},
					EnforcedClaims:   []string{},
				},
			},
		}

		result, err := r.buildAuthenticatorPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, result)
		// Data should be nil because identity payload would be empty
		assert.Nil(t, result.Data)
	})
}

func TestConjurAuthenticatorResource_parseAuthenticatorResponse(t *testing.T) {
	r := &ConjurAuthenticatorResource{}

	t.Run("Minimal fields in response", func(t *testing.T) {
		authenticator := &conjurapi.AuthenticatorResponse{
			AuthenticatorBase: conjurapi.AuthenticatorBase{
				Type:        "jwt",
				Name:        "test-auth",
				Subtype:     nil,
				Enabled:     nil,
				Owner:       nil,
				Data:        nil,
				Annotations: nil,
			},
			Branch: "conjur/authn-jwt",
		}

		data := &ConjurAuthenticatorResourceModel{}
		err := r.parseAuthenticatorResponse(authenticator, data)

		require.NoError(t, err)
		assert.Equal(t, "jwt", data.Type.ValueString())
		assert.Equal(t, "test-auth", data.Name.ValueString())
		assert.True(t, data.Subtype.IsNull())
		assert.True(t, data.Enabled.IsNull())
		assert.True(t, data.Owner.IsNull())
		assert.Nil(t, data.Data)
		assert.Nil(t, data.Annotations)
	})

	t.Run("All response fields", func(t *testing.T) {
		enabled := true
		subtype := "service"
		publicKeysObj := map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
		}

		authenticator := &conjurapi.AuthenticatorResponse{
			AuthenticatorBase: conjurapi.AuthenticatorBase{
				Type:    "jwt",
				Name:    "test-auth",
				Subtype: &subtype,
				Enabled: &enabled,
				Owner: &conjurapi.AuthOwner{
					Kind: "group",
					ID:   "admin-group",
				},
				Data: map[string]interface{}{
					"audience":    "test-audience",
					"jwks_uri":    "https://example.com/jwks",
					"issuer":      "test-issuer",
					"ca_cert":     "-----BEGIN CERTIFICATE-----",
					"public_keys": publicKeysObj,
					"identity": map[string]interface{}{
						"identity_path":      "/identity/path",
						"token_app_property": "app_property",
						"claim_aliases": map[string]interface{}{
							"sub": "subject",
							"aud": "audience",
						},
						"enforced_claims": []interface{}{"sub", "aud", "exp"},
					},
				},
				Annotations: map[string]string{
					"environment": "production",
					"team":        "security",
				},
			},
			Branch: "conjur/authn-jwt",
		}

		data := &ConjurAuthenticatorResourceModel{}
		err := r.parseAuthenticatorResponse(authenticator, data)

		require.NoError(t, err)
		assert.Equal(t, "jwt", data.Type.ValueString())
		assert.Equal(t, "test-auth", data.Name.ValueString())
		assert.Equal(t, "service", data.Subtype.ValueString())
		assert.True(t, data.Enabled.ValueBool())

		// Check Owner
		require.NotNil(t, data.Owner)
		assert.Equal(t, "group", data.Owner.Attributes()["kind"].(types.String).ValueString())
		assert.Equal(t, "admin-group", data.Owner.Attributes()["id"].(types.String).ValueString())

		// Check Data
		require.NotNil(t, data.Data)
		assert.Equal(t, "test-audience", data.Data.Audience.ValueString())
		assert.Equal(t, "https://example.com/jwks", data.Data.JwksURI.ValueString())
		assert.Equal(t, "test-issuer", data.Data.Issuer.ValueString())
		assert.Equal(t, "-----BEGIN CERTIFICATE-----", data.Data.CACert.ValueString())

		// Check PublicKeys JSON marshaling
		publicKeysJSON := data.Data.PublicKeys.ValueString()
		var parsedKeys map[string]interface{}
		err = json.Unmarshal([]byte(publicKeysJSON), &parsedKeys)
		require.NoError(t, err)
		assert.Equal(t, "value1", parsedKeys["key1"])
		assert.Equal(t, "value2", parsedKeys["key2"])

		// Check Identity
		require.NotNil(t, data.Data.Identity)
		assert.Equal(t, "/identity/path", data.Data.Identity.IdentityPath.ValueString())
		assert.Equal(t, "app_property", data.Data.Identity.TokenAppProperty.ValueString())

		require.NotNil(t, data.Data.Identity.ClaimAliases)
		assert.Equal(t, "subject", data.Data.Identity.ClaimAliases["sub"])
		assert.Equal(t, "audience", data.Data.Identity.ClaimAliases["aud"])

		require.NotNil(t, data.Data.Identity.EnforcedClaims)
		assert.Contains(t, data.Data.Identity.EnforcedClaims, "sub")
		assert.Contains(t, data.Data.Identity.EnforcedClaims, "aud")
		assert.Contains(t, data.Data.Identity.EnforcedClaims, "exp")

		// Check Annotations
		assert.Len(t, data.Annotations, 2)
		assert.Equal(t, "production", data.Annotations["environment"])
		assert.Equal(t, "security", data.Annotations["team"])
	})
}
