package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const groupMemberIDSeparator = ":"

var (
	_ resource.Resource                = &conjurMembershipResource{}
	_ resource.ResourceWithConfigure   = &conjurMembershipResource{}
	_ resource.ResourceWithImportState = &conjurMembershipResource{}
)

type conjurMembershipResource struct {
	client api.ClientV2
}

type membershipResourceModel struct {
	ID         types.String `tfsdk:"id"`
	GroupID    types.String `tfsdk:"group_id"`
	MemberKind types.String `tfsdk:"member_kind"`
	MemberID   types.String `tfsdk:"member_id"`
}

func NewConjurMembershipResource() resource.Resource {
	return &conjurMembershipResource{}
}

func (r *conjurMembershipResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_membership"
}

func (r *conjurMembershipResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "CyberArk Secrets Manager membership resource",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Internal ID in format 'group_id|member_kind|member_id'",
			},
			"group_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Secrets Manager group role ID, e.g. 'data/test/test-users'",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"member_kind": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Kind of the member: 'user', 'host', or 'group'",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"member_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Member role ID, e.g. 'data/test/bob'",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *conjurMembershipResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *conjurMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data membershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := validateKind(data.MemberKind.ValueString()); err != nil {
		resp.Diagnostics.AddError("Invalid member_kind", err.Error())
		return
	}

	member := conjurapi.GroupMember{
		ID:   data.MemberID.ValueString(),
		Kind: data.MemberKind.ValueString(),
	}

	if _, err := r.client.AddGroupMember(data.GroupID.ValueString(), member); err != nil {
		resp.Diagnostics.AddError("Failed to add group member", err.Error())
		return
	}

	data.ID = types.StringValue(data.GroupID.ValueString() + groupMemberIDSeparator + data.MemberKind.ValueString() + groupMemberIDSeparator + data.MemberID.ValueString())
	tflog.Trace(ctx, "Created group member resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *conjurMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data membershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := validateKind(data.MemberKind.ValueString()); err != nil {
		resp.Diagnostics.AddError("Invalid member_kind", err.Error())
		return
	}

	account := r.client.GetConfig().Account
	fqMember := fmt.Sprintf("%s:%s:%s", account, data.MemberKind.ValueString(), data.MemberID.ValueString())
	fqGroup := fmt.Sprintf("%s:group:%s", account, data.GroupID.ValueString())

	memberships, err := r.client.RoleMemberships(fqMember)
	if err != nil {
		tflog.Trace(ctx, "Memberships lookup failed; removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	found := false
	for _, m := range memberships {
		if v, ok := m["roleid"]; ok {
			if s, ok := v.(string); ok && s == fqGroup {
				found = true
				break
			}
		}
		if v, ok := m["role"]; ok {
			if s, ok := v.(string); ok && s == fqGroup {
				found = true
				break
			}
		}
		if v, ok := m["id"]; ok {
			if s, ok := v.(string); ok && s == fqGroup {
				found = true
				break
			}
		}
	}

	if !found {
		tflog.Trace(ctx, "Membership not found; removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	if data.ID.IsNull() || data.ID.ValueString() == "" {
		data.ID = types.StringValue(data.GroupID.ValueString() + groupMemberIDSeparator + data.MemberKind.ValueString() + groupMemberIDSeparator + data.MemberID.ValueString())
	}

	tflog.Trace(ctx, "Read group member resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *conjurMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddWarning(
		"Update not supported",
		"All attributes require replacement; Terraform will delete and recreate this resource instead.",
	)
}

func (r *conjurMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data membershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := data.GroupID.ValueString()
	member := conjurapi.GroupMember{
		ID:   data.MemberID.ValueString(),
		Kind: data.MemberKind.ValueString(),
	}

	if _, err := r.client.RemoveGroupMember(groupID, member); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to remove group member, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "Removed group member resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *conjurMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	groupID, kind, memberID, err := splitGroupMemberID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected format: group_id|member_kind|member_id")
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("group_id"), groupID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("member_kind"), kind)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("member_id"), memberID)...)
}

func validateKind(kind string) error {
	switch kind {
	case "user", "host", "group":
		return nil
	default:
		return fmt.Errorf("must be one of: user, host, group")
	}
}

func splitGroupMemberID(id string) (string, string, string, error) {
	parts := strings.Split(id, groupMemberIDSeparator)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("expected 'group_id:member_kind:member_id'")
	}
	return parts[0], parts[1], parts[2], nil
}
