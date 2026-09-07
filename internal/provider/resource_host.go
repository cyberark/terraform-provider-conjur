package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                   = &HostResource{}
	_ resource.ResourceWithConfigure      = &HostResource{}
	_ resource.ResourceWithValidateConfig = &HostResource{}
)

func NewHostResource() resource.Resource {
	return &HostResource{
		typeName:   "conjur_host",
		capability: CapabilityWorkloadAuthnDescriptors,
	}
}

// HostResource defines the resource implementation.
type HostResource struct {
	typeName   string
	capability Capability
	client     api.ClientV2
}

// HostResourceModel describes the resource data model.
type HostResourceModel struct {
	Name             types.String          `tfsdk:"name"`
	Branch           types.String          `tfsdk:"branch"`
	Type             types.String          `tfsdk:"type"`
	Owner            *HostOwnerModel       `tfsdk:"owner"`
	RestrictedTo     types.List            `tfsdk:"restricted_to"`
	AuthnDescriptors []HostAuthnDescriptor `tfsdk:"authn_descriptors"`
	Annotations      map[string]string     `tfsdk:"annotations"`
}

type HostOwnerModel struct {
	Kind types.String `tfsdk:"kind"`
	ID   types.String `tfsdk:"id"`
}

type HostAuthnDescriptor struct {
	Type      types.String      `tfsdk:"type"`
	ServiceID types.String      `tfsdk:"service_id"`
	Data      map[string]string `tfsdk:"data"`
}

func (r *HostResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_host"
}

func (r *HostResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "CyberArk Secrets Manager host resource",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the host",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"branch": schema.StringAttribute{
				MarkdownDescription: "The policy branch of the host",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				MarkdownDescription: "The host type",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"owner": schema.SingleNestedAttribute{
				MarkdownDescription: "Owner of the host",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"kind": schema.StringAttribute{
						MarkdownDescription: "Owner kind (user, group, etc.)",
						Optional:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"id": schema.StringAttribute{
						MarkdownDescription: "Owner identifier",
						Optional:            true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
				},
			},
			"restricted_to": schema.ListAttribute{
				MarkdownDescription: "List of CIDR blocks the host is restricted to",
				ElementType:         types.StringType,
				Optional:            true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},
			"authn_descriptors": schema.ListNestedAttribute{
				MarkdownDescription: "List of authentication descriptors for the host",
				Required:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							MarkdownDescription: "Type of authentication",
							Required:            true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
						},
						"service_id": schema.StringAttribute{
							MarkdownDescription: "Service ID for the authentication type",
							Optional:            true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
						},
						"data": schema.MapAttribute{
							MarkdownDescription: "Map of keys to expected values for the authentication descriptor (e.g. JWT claim names to expected claim values, or other authenticator-specific data), sent to the API as-is. To specify multiple values for a single key (e.g. a JWT `aud` claim that must match more than one audience), use a JSON array string, e.g. `jsonencode([\"app1\", \"app2\"])`; any other value is sent to the API as a single scalar string.",
							ElementType:         types.StringType,
							Optional:            true,
							PlanModifiers: []planmodifier.Map{
								mapplanmodifier.RequiresReplace(),
							},
						},
					},
				},
			},
			"annotations": schema.MapAttribute{
				MarkdownDescription: "Key-value annotations for the host",
				Optional:            true,
				ElementType:         types.StringType,
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *HostResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data HostResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ValidateNonBlank(data.Name, &resp.Diagnostics, "Host name")
	ValidateBranch(data.Branch, &resp.Diagnostics, "branch")

	// Validate authn_descriptors are not empty
	if len(data.AuthnDescriptors) == 0 {
		resp.Diagnostics.AddError(
			"Invalid authn_descriptors",
			"At least one authentication descriptor is required.",
		)
	}

	// Validate each descriptor's type is set.
	for i, descriptor := range data.AuthnDescriptors {
		if descriptor.Type.ValueString() == "" {
			resp.Diagnostics.AddError(
				"Invalid authn_descriptors",
				fmt.Sprintf("authn_descriptors[%d] is missing a type.", i),
			)
		}
	}
}

func (r *HostResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	clients, ok := configureConjurClient(req, resp, r.capability, r.typeName)
	if !ok {
		return
	}

	r.client = clients.conjurClient
}

func (r *HostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data HostResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	newHost, err := r.buildHostPayload(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Host Payload", fmt.Sprintf("Could not build host payload: %s", err))
		return
	}

	_, err = r.client.CreateWorkload(*newHost)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create host, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "created host resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *HostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data HostResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostID := fullyQualifiedID(r.client, "host", fmt.Sprintf("%s/%s", data.Branch.ValueString(), data.Name.ValueString()))
	exists, err := r.client.RoleExists(hostID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading Secrets Manager host",
			fmt.Sprintf("Unable to check if host %q exists: %s", hostID, err),
		)
		return
	}

	// Remove the host if it has been removed from Conjur (or is inaccessible to the provider)
	if !exists {
		resp.Diagnostics.AddWarning("Host Not Found", fmt.Sprintf("The host %q was not found in Secrets Manager and will be removed from the state. If you did not expect this, please check your Secrets Manager instance to ensure the host exists and can be managed by the provider identity.", hostID))
		resp.State.RemoveResource(ctx)
		return
	}

	// Assume state is unchanged since there isn't full read support via the APIs
	tflog.Trace(ctx, "read host resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update replaces the host by deleting and recreating it since there's no PATCH support
func (r *HostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	// This should never be called since in-place updates are not supported by the API. Therefore any attribute changes
	// require replacement of the resource (Delete + Create) as denoted by the plan modifiers.
	resp.Diagnostics.AddWarning("Update not supported", "Host resources require replacement for any changes, so update is not supported. Please recreate the resource with the desired changes.")
}

func (r *HostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data HostResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteWorkload(fmt.Sprintf("%s/%s", data.Branch.ValueString(), data.Name.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete host, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "deleted host resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// buildHostPayload maps the resource model to an API payload
func (r *HostResource) buildHostPayload(data *HostResourceModel) (*conjurapi.Workload, error) {

	// Initialize with required fields
	host := conjurapi.Workload{
		Name:   data.Name.ValueString(),
		Branch: data.Branch.ValueString(),
	}
	authnDescriptors := make([]conjurapi.AuthnDescriptor, len(data.AuthnDescriptors))
	for i, v := range data.AuthnDescriptors {
		descriptor := conjurapi.AuthnDescriptor{
			Type: v.Type.ValueString(),
		}

		if v.ServiceID.ValueString() != "" {
			descriptor.ServiceID = v.ServiceID.ValueString()
		}

		if len(v.Data) > 0 {
			// The client's AuthnDescriptor.Data is map[string]any (structure
			// varies by authenticator type). A JSON array value is decoded
			// into a []string; otherwise it is sent as-is.
			descriptorData := make(map[string]any, len(v.Data))
			for k, val := range v.Data {
				descriptorData[k] = claimValueToAPI(val)
			}
			descriptor.Data = descriptorData
		}
		authnDescriptors[i] = descriptor
	}
	host.AuthnDescriptors = authnDescriptors

	// Add optional fields only if they are set
	if !data.Type.IsNull() && !data.Type.IsUnknown() {
		host.Type = data.Type.ValueString()
	}

	if len(data.RestrictedTo.Elements()) > 0 {
		restrictedTo := make([]string, len(data.RestrictedTo.Elements()))
		for i, v := range data.RestrictedTo.Elements() {
			restrictedTo[i] = v.(types.String).ValueString()
		}
		host.RestrictedTo = restrictedTo
	}

	if data.Owner != nil {
		host.Owner = &conjurapi.Owner{
			Kind: data.Owner.Kind.ValueString(),
			Id:   data.Owner.ID.ValueString(),
		}
	}

	if len(data.Annotations) > 0 {
		host.Annotations = data.Annotations
	}

	return &host, nil
}

// claimValueToAPI decodes a JSON array string into []string, or returns the raw string.
// Values starting with "[" are parsed as JSON;
// invalid JSON or non-[]string values are returned as-is.
func claimValueToAPI(raw string) any {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "[") {
		return raw
	}

	var values []string
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return raw
	}
	return values
}
