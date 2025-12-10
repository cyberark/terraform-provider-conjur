package provider

import (
	"context"
	"fmt"

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
	_ resource.Resource                   = &ConjurHostResource{}
	_ resource.ResourceWithConfigure      = &ConjurHostResource{}
	_ resource.ResourceWithValidateConfig = &ConjurHostResource{}
)

func NewConjurHostResource() resource.Resource {
	return &ConjurHostResource{}
}

// ConjurHostResource defines the resource implementation.
type ConjurHostResource struct {
	client api.ClientV2
}

// ConjurHostResourceModel describes the resource data model.
type ConjurHostResourceModel struct {
	Name             types.String                `tfsdk:"name"`
	Branch           types.String                `tfsdk:"branch"`
	Type             types.String                `tfsdk:"type"`
	Owner            *ConjurHostOwnerModel       `tfsdk:"owner"`
	RestrictedTo     types.List                  `tfsdk:"restricted_to"`
	AuthnDescriptors []ConjurHostAuthnDescriptor `tfsdk:"authn_descriptors"`
	Annotations      map[string]string           `tfsdk:"annotations"`
}

type ConjurHostOwnerModel struct {
	Kind types.String `tfsdk:"kind"`
	ID   types.String `tfsdk:"id"`
}

type ConjurHostAuthnDescriptorData struct {
	Claims map[string]string `tfsdk:"claims"`
}

type ConjurHostAuthnDescriptor struct {
	Type      types.String                   `tfsdk:"type"`
	ServiceID types.String                   `tfsdk:"service_id"`
	Data      *ConjurHostAuthnDescriptorData `tfsdk:"data"`
}

func (r *ConjurHostResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_host"
}

func (r *ConjurHostResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
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
						"data": schema.SingleNestedAttribute{
							MarkdownDescription: "Additional data for the authentication descriptor",
							Optional:            true,
							Attributes: map[string]schema.Attribute{
								"claims": schema.MapAttribute{
									MarkdownDescription: "Map of claim keys to expected values",
									ElementType:         types.StringType,
									Optional:            true,
									PlanModifiers: []planmodifier.Map{
										mapplanmodifier.RequiresReplace(),
									},
								},
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

func (r *ConjurHostResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data ConjurHostResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ValidateNonEmpty(data.Name, &resp.Diagnostics, "Host name")
	ValidateBranch(data.Branch, &resp.Diagnostics, "branch")

	// Validate authn_descriptors are not empty
	if len(data.AuthnDescriptors) == 0 {
		resp.Diagnostics.AddError(
			"Invalid authn_descriptors",
			"At least one authentication descriptor is required.",
		)
	}
}

func (r *ConjurHostResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(api.ClientV2)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected api.ClientV2, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *ConjurHostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConjurHostResourceModel

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

func (r *ConjurHostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConjurHostResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	// Just validate the host exists in Conjur since we can't fully hydrate the state via API currently
	hostID := fmt.Sprintf("host:%s/%s", data.Branch.ValueString(), data.Name.ValueString())
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
func (r *ConjurHostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// This should never be called since in-place updates are not supported by the API. Therefore any attribute changes
	// require replacement of the resource (Delete + Create) as denoted by the plan modifiers.
	resp.Diagnostics.AddWarning("Update not supported", "Host resources require replacement for any changes, so update is not supported. Please recreate the resource with the desired changes.")
}

func (r *ConjurHostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConjurHostResourceModel

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
func (r *ConjurHostResource) buildHostPayload(data *ConjurHostResourceModel) (*conjurapi.Workload, error) {

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

		if v.Data != nil && len(v.Data.Claims) > 0 {
			descriptor.Data = &conjurapi.AuthnDescriptorData{
				Claims: v.Data.Claims,
			}
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
