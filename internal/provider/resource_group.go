package provider

import (
	"context"
	"fmt"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/policy"
	"github.com/doodlesbykumbi/conjur-policy-go/pkg/conjurpolicy"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"gopkg.in/yaml.v3"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &ConjurGroupResource{}

func NewConjurGroupResource() resource.Resource {
	return &ConjurGroupResource{}
}

// ConjurGroupResource defines the resource implementation.
type ConjurGroupResource struct {
	client *conjurapi.Client
}

// ConjurGroupResourceModel describes the resource data model.
type ConjurGroupResourceModel struct {
	Name        types.String           `tfsdk:"name"`
	Branch      types.String           `tfsdk:"branch"`
	Owner       *ConjurGroupOwnerModel `tfsdk:"owner"`
	Annotations map[string]string      `tfsdk:"annotations"`
}

type ConjurGroupOwnerModel struct {
	Kind types.String `tfsdk:"kind"`
	ID   types.String `tfsdk:"id"`
}

func (r *ConjurGroupResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (r *ConjurGroupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Conjur Group resource. This resource creates a group in Conjur using policy. Note that this is a write-only resource - import and exact state tracking are not supported due to API limitations.",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the group",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"branch": schema.StringAttribute{
				MarkdownDescription: "The policy branch of the group",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"owner": schema.SingleNestedAttribute{
				MarkdownDescription: "Owner of the group",
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
			"annotations": schema.MapAttribute{
				MarkdownDescription: "Key-value annotations for the group",
				Optional:            true,
				ElementType:         types.StringType,
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *ConjurGroupResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*conjurapi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *conjurapi.Client, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *ConjurGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConjurGroupResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Generate the policy for creating the group
	groupPolicy, err := r.generateGroupPolicy(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Generating Policy", fmt.Sprintf("Could not generate group policy: %s", err))
		return
	}

	// Apply the policy to Conjur
	err = policy.ApplyPolicy(r.client, groupPolicy, data.Branch.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Applying Policy", fmt.Sprintf("Could not apply group policy: %s", err))
		return
	}

	tflog.Trace(ctx, "created group resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ConjurGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// All attributes are marked RequiresReplace, so this should never be called
	resp.Diagnostics.AddError("Update Not Supported", "This resource does not support in-place updates. Please recreate the resource to apply changes.")
}

func (r *ConjurGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConjurGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Just validate the group exists in Conjur since we can't fully hydrate the state via API currently
	groupID := fmt.Sprintf("group:%s/%s", data.Branch.ValueString(), data.Name.ValueString())
	exists, err := r.client.RoleExists(groupID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading Conjur group",
			fmt.Sprintf("Unable to check if group %q exists: %s", groupID, err),
		)
		return
	}

	// Remove the group if it has been removed from Conjur (or is inaccessible to the provider)
	if !exists {
		resp.Diagnostics.AddWarning("Group Not Found", fmt.Sprintf("The group %q was not found in Conjur and will be removed from the state. If you did not expect this, please check your Conjur instance to ensure the group exists and can be managed by the provider identity.", groupID))
		resp.State.RemoveResource(ctx)
		return
	}

	// Assume state is unchanged since there isn't full read support via the APIs
	tflog.Trace(ctx, "read group resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConjurGroupResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Generate policy to delete the group
	groupPolicy, err := r.generateGroupDeletionPolicy(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Generating Deletion Policy", fmt.Sprintf("Could not generate group deletion policy: %s", err))
		return
	}

	// Apply the deletion policy
	err = policy.ApplyPolicy(r.client, groupPolicy, data.Branch.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Applying Deletion Policy", fmt.Sprintf("Could not apply group deletion policy: %s", err))
		return
	}

	tflog.Trace(ctx, "deleted group resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// generateGroupPolicy creates a Conjur policy for creating a group
func (r *ConjurGroupResource) generateGroupPolicy(data *ConjurGroupResourceModel) (string, error) {
	group := conjurpolicy.Group{
		Id: data.Name.ValueString(),
	}

	// Add owner if specified
	if data.Owner != nil {
		ownerKind, err := conjurpolicy.KindString(data.Owner.Kind.ValueString())
		if err != nil {
			return "", fmt.Errorf("invalid owner kind: %w", err)
		}
		group.Owner = conjurpolicy.ResourceRef{
			Kind: ownerKind,
			Id:   data.Owner.ID.ValueString(),
		}
	}

	if len(data.Annotations) > 0 {
		annotations := make(map[string]interface{})
		for k, v := range data.Annotations {
			annotations[k] = v
		}
		group.Annotations = annotations
	}

	// Create policy body with the group
	policyStatements := conjurpolicy.PolicyStatements{group}

	// Marshal to YAML
	yamlBytes, err := yaml.Marshal(policyStatements)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy to YAML: %w", err)
	}

	return string(yamlBytes), nil
}

// generateGroupDeletionPolicy creates a policy to delete a group
func (r *ConjurGroupResource) generateGroupDeletionPolicy(data *ConjurGroupResourceModel) (string, error) {
	delete := conjurpolicy.Delete{
		Record: conjurpolicy.ResourceRef{
			Kind: conjurpolicy.KindGroup,
			Id:   data.Name.ValueString(),
		},
	}

	// Create policy body with the delete statement
	policyStatements := conjurpolicy.PolicyStatements{delete}
	// Marshal to YAML
	yamlBytes, err := yaml.Marshal(policyStatements)
	if err != nil {
		return "", fmt.Errorf("failed to marshal deletion policy to YAML: %w", err)
	}

	return string(yamlBytes), nil
}
