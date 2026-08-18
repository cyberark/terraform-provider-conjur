package provider

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Capability identifies a Secrets Manager feature that a resource or data source
// depends on. The three deployment flavors (SaaS, Self-Hosted, OSS)
// expose different subsets of the V2 API, so rather than each resource probing
// the environment inline, it declares the capability it needs and the provider
// refuses to talk to a deployment that does not offer it.
//
// Doing this declaratively keeps enablement a one-line change in
// the capabilities map instead of an edit to every affected resource.
type Capability int

const (
	// CapabilityCoreV2 covers the V2 endpoints every deployment exposes: policy
	// load, branches, permissions, authenticators and single-secret retrieval.
	CapabilityCoreV2 Capability = iota
	// CapabilityStaticSecretsV2 backs conjur_secret's Create and Read
	// (secret_static_v2.go).
	CapabilityStaticSecretsV2
	CapabilityGroupsV2
	CapabilityIssuersV2
	CapabilityWorkloadAuthnDescriptors
	CapabilityBatchSecrets
	CapabilitySWA

	// capabilityCount must stay last: a new constant added above it fails the
	// exhaustiveness tests until the support matrix and name map are updated too.
	capabilityCount
)

// capabilityDef bundles the human-readable name (used in diagnostics) with the
// environments that expose the capability.
type capabilityDef struct {
	name         string
	environments []conjurapi.EnvironmentType
}

// capabilities is the single source of truth for capability metadata. This is
// the single point of change when Self-Hosted gains parity: add
// conjurapi.EnvironmentSH to the relevant environments slice.
//
// Capabilities available everywhere list all three environments rather than
// being omitted, so that a missing row is unambiguously a mistake (asserted by
// TestCapabilityDefinitionsAreExhaustive) and never a silently open gate.
//
// An environment is the only axis here because conjur-api-go performs no
// per-environment endpoint dispatch: a method either works or returns
// "not supported", never a different call.
var capabilities = map[Capability]capabilityDef{
	CapabilityCoreV2: {
		name:         "Core V2 API",
		environments: []conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS, conjurapi.EnvironmentSH, conjurapi.EnvironmentOSS},
	},
	CapabilityStaticSecretsV2: {
		name:         "Static secrets (V2 API)",
		environments: []conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS},
	},
	CapabilityGroupsV2: {
		name:         "Groups",
		environments: []conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS, conjurapi.EnvironmentSH, conjurapi.EnvironmentOSS},
	},
	CapabilityIssuersV2: {
		name:         "Certificate issuers",
		environments: []conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS},
	},
	CapabilityWorkloadAuthnDescriptors: {
		name:         "Workload authentication descriptors",
		environments: []conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS},
	},
	// Batch retrieval is SaaS-only: the SDK rejects it outright off SaaS
	// (secrets_batch_v2.go BatchRetrieveSecrets).
	CapabilityBatchSecrets: {
		name:         "Batch secret retrieval",
		environments: []conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS},
	},
	CapabilitySWA: {
		name:         "Secure Workload Access (SWA)",
		environments: []conjurapi.EnvironmentType{conjurapi.EnvironmentSaaS},
	},
}

func (c Capability) String() string {
	if def, ok := capabilities[c]; ok {
		return def.name
	}
	return fmt.Sprintf("Capability(%d)", int(c))
}

// environmentNames renders environment types for a diagnostic, e.g.
// "Idira Secrets Manager, SaaS or Idira Secrets Manager, Self-Hosted".
func environmentNames(envs []conjurapi.EnvironmentType) string {
	names := make([]string, 0, len(envs))
	for _, env := range envs {
		// FullName has a pointer receiver, so take an addressable copy.
		env := env
		names = append(names, env.FullName())
	}

	switch len(names) {
	case 0:
		return "no supported environment"
	case 1:
		return names[0]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
	}
}

// requireCapability reports whether the configured deployment offers c, returning
// an error diagnostic naming resourceName when it does not.
//
// It returns no diagnostics when the capability cannot be determined - a nil
// client (unresolved JWT during plan; see the nil-client contract) or a Config
// with no Environment set. Blocking in those cases would fail configurations
// that are in fact valid; the per-operation nil-client checks handle the former
// and conjurapi.Config.Validate rejects the latter before a client is ever built.
func requireCapability(clients *providerClients, c Capability, resourceName string) diag.Diagnostics {
	var diags diag.Diagnostics

	if clients == nil || clients.conjurClient == nil {
		return diags
	}

	cfg := clients.conjurClient.GetConfig()
	if cfg.Environment == "" {
		return diags
	}

	def, ok := capabilities[c]
	if !ok {
		// A capability with no row is a programming error, not a user error, but
		// failing closed beats silently granting access to an unsupported API.
		diags.AddError(
			fmt.Sprintf("%s is not available", resourceName),
			fmt.Sprintf("The provider has no support matrix entry for capability %q. This is a bug in the provider; please report it.", c),
		)
		return diags
	}

	if slices.Contains(def.environments, cfg.Environment) {
		return diags
	}

	environment := cfg.Environment
	diags.AddError(
		fmt.Sprintf("%s is not supported on %s", resourceName, environment.FullName()),
		fmt.Sprintf(
			"%s requires %s, which is only available on %s. The configured appliance URL (%s) resolves to %s.\n\n"+
				"Remove %s from your configuration when targeting this deployment, or point the provider at a deployment that supports it.",
			resourceName,
			c,
			environmentNames(def.environments),
			cfg.ApplianceURL,
			environment.FullName(),
			resourceName,
		),
	)
	return diags
}

// configureProviderClients performs the ProviderData type assertion shared by
// every resource, data source and ephemeral resource, then enforces c.
//
// A nil ProviderData means Configure ran before the provider was configured; that
// is not an error, so it reports false without diagnostics.
func configureProviderClients(providerData any, c Capability, resourceName string, diags *diag.Diagnostics) (*providerClients, bool) {
	if providerData == nil {
		return nil, false
	}

	clients, ok := providerData.(*providerClients)
	if !ok {
		AddUnexpectedConfigureTypeError(diags, "*providerClients", providerData)
		return nil, false
	}

	diags.Append(requireCapability(clients, c, resourceName)...)
	if diags.HasError() {
		return nil, false
	}

	return clients, true
}

// configureConjurClient resolves the Conjur V2 client for a resource, gated on c.
func configureConjurClient(req resource.ConfigureRequest, resp *resource.ConfigureResponse, c Capability, resourceName string) (*providerClients, bool) {
	return configureProviderClients(req.ProviderData, c, resourceName, &resp.Diagnostics)
}

// configureDataSourceClient is the datasource.ConfigureRequest counterpart of
// configureConjurClient. The framework uses distinct request/response types per
// interface, so these thin wrappers exist purely to avoid repeating the
// unwrapping at every call site.
func configureDataSourceClient(req datasource.ConfigureRequest, resp *datasource.ConfigureResponse, c Capability, resourceName string) (*providerClients, bool) {
	return configureProviderClients(req.ProviderData, c, resourceName, &resp.Diagnostics)
}

// configureEphemeralClient is the ephemeral.ConfigureRequest counterpart of
// configureConjurClient.
func configureEphemeralClient(req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse, c Capability, resourceName string) (*providerClients, bool) {
	return configureProviderClients(req.ProviderData, c, resourceName, &resp.Diagnostics)
}
