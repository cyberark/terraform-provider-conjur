package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConjurHostResource_buildHostPayload(t *testing.T) {
	r := &ConjurHostResource{}

	t.Run("Minimum host fields provided", func(t *testing.T) {
		data := &ConjurHostResourceModel{
			Name:   types.StringValue("test-host"),
			Branch: types.StringValue("data"),
			Type:   types.StringNull(),
			AuthnDescriptors: []ConjurHostAuthnDescriptor{
				{
					Type:      types.StringValue("api_key"),
					ServiceID: types.StringNull(),
					Data:      nil,
				},
			},
			RestrictedTo: types.ListNull(types.StringType),
			Owner:        nil,
			Annotations:  nil,
		}

		host, err := r.buildHostPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, host)
		assert.Equal(t, "test-host", host.Name)
		assert.Equal(t, "data", host.Branch)
		assert.Empty(t, host.Type)
		assert.Nil(t, host.Owner)
		assert.Empty(t, host.RestrictedTo)
		assert.Empty(t, host.Annotations)
		assert.Len(t, host.AuthnDescriptors, 1)
		assert.Equal(t, "api_key", host.AuthnDescriptors[0].Type)
		assert.Empty(t, host.AuthnDescriptors[0].ServiceID)
		assert.Nil(t, host.AuthnDescriptors[0].Data)
	})

	t.Run("All host fields provided", func(t *testing.T) {
		restrictedToElements := []types.String{
			types.StringValue("192.168.1.0/24"),
			types.StringValue("10.0.0.0/8"),
		}
		restrictedToList, _ := types.ListValueFrom(nil, types.StringType, restrictedToElements)

		data := &ConjurHostResourceModel{
			Name:         types.StringValue("test-host"),
			Branch:       types.StringValue("data/production"),
			Type:         types.StringValue("jenkins"),
			RestrictedTo: restrictedToList,
			Owner: &ConjurHostOwnerModel{
				Kind: types.StringValue("group"),
				ID:   types.StringValue("jenkins-admins"),
			},
			AuthnDescriptors: []ConjurHostAuthnDescriptor{
				{
					Type:      types.StringValue("jwt"),
					ServiceID: types.StringValue("jwt-service"),
					Data: &ConjurHostAuthnDescriptorData{
						Claims: map[string]string{
							"sub": "test-subject",
							"aud": "test-audience",
						},
					},
				},
				{
					Type:      types.StringValue("jwt"),
					ServiceID: types.StringValue("jenkins"),
					Data:      nil,
				},
			},
			Annotations: map[string]string{
				"environment": "production",
				"team":        "security",
			},
		}

		host, err := r.buildHostPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, host)
		assert.Equal(t, "test-host", host.Name)
		assert.Equal(t, "data/production", host.Branch)
		assert.Equal(t, "jenkins", host.Type)

		// Check Owner
		require.NotNil(t, host.Owner)
		assert.Equal(t, "group", host.Owner.Kind)
		assert.Equal(t, "jenkins-admins", host.Owner.Id)

		// Check RestrictedTo
		assert.Len(t, host.RestrictedTo, 2)
		assert.Contains(t, host.RestrictedTo, "192.168.1.0/24")
		assert.Contains(t, host.RestrictedTo, "10.0.0.0/8")

		// Check AuthnDescriptors
		assert.Len(t, host.AuthnDescriptors, 2)

		// First descriptor with claims
		assert.Equal(t, "jwt", host.AuthnDescriptors[0].Type)
		assert.Equal(t, "jwt-service", host.AuthnDescriptors[0].ServiceID)
		require.NotNil(t, host.AuthnDescriptors[0].Data)
		assert.Equal(t, "test-subject", host.AuthnDescriptors[0].Data.Claims["sub"])
		assert.Equal(t, "test-audience", host.AuthnDescriptors[0].Data.Claims["aud"])

		// Second descriptor without claims
		assert.Equal(t, "jwt", host.AuthnDescriptors[1].Type)
		assert.Equal(t, "jenkins", host.AuthnDescriptors[1].ServiceID)
		assert.Nil(t, host.AuthnDescriptors[1].Data)

		// Check Annotations
		assert.Len(t, host.Annotations, 2)
		assert.Equal(t, "production", host.Annotations["environment"])
		assert.Equal(t, "security", host.Annotations["team"])
	})

	t.Run("Authn descriptor with empty service ID", func(t *testing.T) {
		data := &ConjurHostResourceModel{
			Name:   types.StringValue("test-host"),
			Branch: types.StringValue("data"),
			Type:   types.StringNull(),
			AuthnDescriptors: []ConjurHostAuthnDescriptor{
				{
					Type:      types.StringValue("api_key"),
					ServiceID: types.StringValue(""),
					Data:      nil,
				},
			},
			RestrictedTo: types.ListNull(types.StringType),
			Owner:        nil,
			Annotations:  nil,
		}

		host, err := r.buildHostPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, host)
		assert.Len(t, host.AuthnDescriptors, 1)
		assert.Equal(t, "api_key", host.AuthnDescriptors[0].Type)
		assert.Empty(t, host.AuthnDescriptors[0].ServiceID)
	})

	t.Run("Authn descriptor with empty claims", func(t *testing.T) {
		data := &ConjurHostResourceModel{
			Name:   types.StringValue("test-host"),
			Branch: types.StringValue("data"),
			Type:   types.StringNull(),
			AuthnDescriptors: []ConjurHostAuthnDescriptor{
				{
					Type:      types.StringValue("jwt"),
					ServiceID: types.StringValue("jwt-service"),
					Data: &ConjurHostAuthnDescriptorData{
						Claims: map[string]string{},
					},
				},
			},
			RestrictedTo: types.ListNull(types.StringType),
			Owner:        nil,
			Annotations:  nil,
		}

		host, err := r.buildHostPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, host)
		assert.Len(t, host.AuthnDescriptors, 1)
		assert.Equal(t, "jwt", host.AuthnDescriptors[0].Type)
		assert.Equal(t, "jwt-service", host.AuthnDescriptors[0].ServiceID)
		assert.Nil(t, host.AuthnDescriptors[0].Data) // Should be nil due to empty claims check
	})

	t.Run("Unknown fields are empty", func(t *testing.T) {
		data := &ConjurHostResourceModel{
			Name:   types.StringValue("test-host"),
			Branch: types.StringValue("data"),
			Type:   types.StringUnknown(),
			AuthnDescriptors: []ConjurHostAuthnDescriptor{
				{
					Type:      types.StringValue("jwt"),
					ServiceID: types.StringUnknown(),
					Data:      nil,
				},
			},
			RestrictedTo: types.ListNull(types.StringType),
			Owner:        nil,
			Annotations:  nil,
		}

		host, err := r.buildHostPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, host)
		// Should not be set when unknown
		assert.Empty(t, host.Type)
		assert.Empty(t, host.AuthnDescriptors[0].ServiceID)
	})

	t.Run("Empty restricted_to list", func(t *testing.T) {
		emptyList, _ := types.ListValue(types.StringType, []attr.Value{})

		data := &ConjurHostResourceModel{
			Name:   types.StringValue("test-host"),
			Branch: types.StringValue("data"),
			Type:   types.StringNull(),
			AuthnDescriptors: []ConjurHostAuthnDescriptor{
				{
					Type:      types.StringValue("jwt"),
					ServiceID: types.StringNull(),
					Data:      nil,
				},
			},
			RestrictedTo: emptyList,
			Owner:        nil,
			Annotations:  nil,
		}

		host, err := r.buildHostPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, host)
		assert.Empty(t, host.RestrictedTo)
	})

	t.Run("Single restricted_to element", func(t *testing.T) {
		restrictedToElements := []types.String{types.StringValue("127.0.0.1/32")}
		restrictedToList, _ := types.ListValueFrom(context.Background(), types.StringType, restrictedToElements)

		data := &ConjurHostResourceModel{
			Name:   types.StringValue("test-host"),
			Branch: types.StringValue("data"),
			Type:   types.StringNull(),
			AuthnDescriptors: []ConjurHostAuthnDescriptor{
				{
					Type:      types.StringValue("jwt"),
					ServiceID: types.StringNull(),
					Data:      nil,
				},
			},
			RestrictedTo: restrictedToList,
			Owner:        nil,
			Annotations:  nil,
		}

		host, err := r.buildHostPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, host)
		assert.Len(t, host.RestrictedTo, 1)
		assert.Equal(t, "127.0.0.1/32", host.RestrictedTo[0])
	})

	t.Run("Empty annotations", func(t *testing.T) {
		data := &ConjurHostResourceModel{
			Name:   types.StringValue("test-host"),
			Branch: types.StringValue("data"),
			Type:   types.StringNull(),
			AuthnDescriptors: []ConjurHostAuthnDescriptor{
				{
					Type:      types.StringValue("jwt"),
					ServiceID: types.StringNull(),
					Data:      nil,
				},
			},
			RestrictedTo: types.ListNull(types.StringType),
			Owner:        nil,
			Annotations:  map[string]string{},
		}

		host, err := r.buildHostPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, host)
		assert.Empty(t, host.Annotations)
	})

	t.Run("Multiple authn descriptors", func(t *testing.T) {
		data := &ConjurHostResourceModel{
			Name:   types.StringValue("test-host"),
			Branch: types.StringValue("data"),
			Type:   types.StringNull(),
			AuthnDescriptors: []ConjurHostAuthnDescriptor{
				{
					Type:      types.StringValue("jwt"),
					ServiceID: types.StringValue("jwt-service"),
					Data: &ConjurHostAuthnDescriptorData{
						Claims: map[string]string{"sub": "user1"},
					},
				},
				{
					Type:      types.StringValue("api_key"),
					ServiceID: types.StringValue(""),
					Data:      nil,
				},
				{
					Type:      types.StringValue("ldap"),
					ServiceID: types.StringValue("ldap-service"),
					Data: &ConjurHostAuthnDescriptorData{
						Claims: map[string]string{}, // Empty claims
					},
				},
			},
			RestrictedTo: types.ListNull(types.StringType),
			Owner:        nil,
			Annotations:  nil,
		}

		host, err := r.buildHostPayload(data)

		require.NoError(t, err)
		assert.NotNil(t, host)
		assert.Len(t, host.AuthnDescriptors, 3)

		// First descriptor with claims
		assert.Equal(t, "jwt", host.AuthnDescriptors[0].Type)
		assert.Equal(t, "jwt-service", host.AuthnDescriptors[0].ServiceID)
		require.NotNil(t, host.AuthnDescriptors[0].Data)
		assert.Equal(t, "user1", host.AuthnDescriptors[0].Data.Claims["sub"])

		// Second descriptor without service ID or data
		assert.Equal(t, "api_key", host.AuthnDescriptors[1].Type)
		assert.Empty(t, host.AuthnDescriptors[1].ServiceID)
		assert.Nil(t, host.AuthnDescriptors[1].Data)

		// Third descriptor with empty claims (should result in nil Data)
		assert.Equal(t, "ldap", host.AuthnDescriptors[2].Type)
		assert.Equal(t, "ldap-service", host.AuthnDescriptors[2].ServiceID)
		assert.Nil(t, host.AuthnDescriptors[2].Data)
	})
}
