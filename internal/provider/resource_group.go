package provider

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/cyberark/terraform-provider-conjur/internal/policy"
	"github.com/doodlesbykumbi/conjur-policy-go/pkg/conjurpolicy"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"gopkg.in/yaml.v3"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                   = &GroupResource{}
	_ resource.ResourceWithConfigure      = &GroupResource{}
	_ resource.ResourceWithImportState    = &GroupResource{}
	_ resource.ResourceWithModifyPlan     = &GroupResource{}
	_ resource.ResourceWithValidateConfig = &GroupResource{}
)

// groupOwnerAttrTypes is the attr.Type map for the "owner" nested attribute.
// Derived from ownerToObject (owner.go) instead of a second
// literal, so the two can't drift apart if the owner shape ever changes.
var groupOwnerAttrTypes = ownerToObject(nil).AttributeTypes(context.Background())

// groupNamePattern matches a string containing no '/'.
var groupNamePattern = regexp.MustCompile(`^[^/]*$`)

func NewGroupResource() resource.Resource {
	return &GroupResource{
		resourceBase[api.ClientV2]{
			conjurComponent(
				"conjur_group",
				CapabilityGroupsV2,
			),
		},
	}
}

// GroupResource defines the resource implementation.
//
// This resource has two backends, selected per call by isSaaS. On Secrets
// Manager, SaaS it talks to the V2 /groups REST API directly for
// Create/Read/Delete/Import. On Self-Hosted and OSS it keeps the provider's
// original behavior: groups are created and deleted via generated Conjur
// policy YAML, and import is refused because those deployments have no
// reliable way to read a group back by identifier.
//
// name and branch force replace on both backends. Whether owner and
// annotations force replace depends on the backend, so ModifyPlan decides.
//
// annotations are updated in place on SaaS. The V2 PATCH endpoint merges (it
// adds and overwrites keys but never removes them), so Update deletes each
// removed key individually and PATCHes only for added or changed keys. On
// Self-Hosted/OSS any annotations change replaces the resource, as before.
//
// owner is different: the V2 Group model has no owner field at all (the
// create/update endpoints reject it outright). To avoid breaking a pre-existing
// conjur_group that already has owner set, owner on SaaS is inert rather than rejected: ValidateConfig
// warns instead of erroring, and ModifyPlan never forces a replacement for it
// there. On Self-Hosted/OSS owner keeps its original behavior: any change
// replaces the resource.
//
// Update is therefore only reachable on SaaS. It still hard-errors on
// Self-Hosted/OSS, where owner and annotations force replace and Update was
// never supported.
type GroupResource struct {
	resourceBase[api.ClientV2]
}

// GroupResourceModel describes the resource data model.
type GroupResourceModel struct {
	Name        types.String      `tfsdk:"name"`
	Branch      types.String      `tfsdk:"branch"`
	Owner       types.Object      `tfsdk:"owner"`
	Annotations map[string]string `tfsdk:"annotations"`
}

func (r *GroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "CyberArk Secrets Manager Group resource. On Secrets Manager, SaaS `terraform import` " +
			"is supported, but `owner` is not: setting it produces a warning rather than an error, so pre-existing " +
			"configurations keep working. On Self-Hosted and OSS deployments `owner` is fully supported but " +
			"write-only (import is not supported), and any change to it replaces the resource. `annotations` is " +
			"updated in place on Secrets Manager, SaaS; on Self-Hosted and OSS any change to it replaces the " +
			"resource. `name` and `branch` replace the resource on any change, on both deployment types. " +
			"Replacing the resource deletes and recreates the group, which drops its memberships and any " +
			"permissions granted to it. The provider identity needs policy load privileges on `branch` on " +
			"Self-Hosted and OSS, and the corresponding group-management permissions on Secrets Manager, SaaS. " +
			"The import ID format is `<branch>/<name>` (import is supported on Secrets Manager, SaaS only).",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the group. Must not contain `/` or be `.` or `..`.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(groupNamePattern, "must not contain '/'"),
					noDotSegmentsValidator{},
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
				MarkdownDescription: "Owner of the group. Fully supported on Self-Hosted and OSS: any change to " +
					"it replaces the resource there. Not supported on Secrets Manager, SaaS: setting this " +
					"attribute produces a warning, not an error, and has no effect there, and changing it does " +
					"not replace the resource.",
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"kind": schema.StringAttribute{
						MarkdownDescription: "Owner kind (user, group, etc.)",
						Optional:            true,
					},
					"id": schema.StringAttribute{
						MarkdownDescription: "Owner identifier",
						Optional:            true,
					},
				},
				// owner's RequiresReplace is decided in ModifyPlan, not here: it
				// depends on the backend, which is per-provider-configuration and
				// only known from the Configured instance. See ModifyPlan.
			},
			"annotations": schema.MapAttribute{
				MarkdownDescription: "Key-value annotations for the group. Keys must not be empty or contain a `.` or `..` path segment. On Secrets " +
					"Manager, SaaS, changes are applied in place: added and changed keys via a merging update, " +
					"and removed keys by deleting each one individually. On Self-Hosted and OSS deployments any " +
					"change to this attribute replaces the resource.",
				Optional:    true,
				ElementType: types.StringType,
				// Empty keys are rejected on every backend: the per-key delete
				// endpoint has no way to address one. '.'/'..' segments are
				// rejected because a proxy that decodes %2F would resolve them
				// as path traversal in that endpoint's URL.
				Validators: []validator.Map{
					mapvalidator.KeysAre(stringvalidator.LengthAtLeast(1), noDotSegmentsValidator{}),
				},
				// annotations' RequiresReplace is decided in ModifyPlan, for the
				// same reason as owner's.
			},
		},
	}
}

func (r *GroupResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	// Read attribute by attribute: GroupResourceModel's map[string]string can't hold an unknown annotations value.
	var data GroupResourceModel
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("name"), &data.Name)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("branch"), &data.Branch)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("owner"), &data.Owner)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ValidateNonBlank(data.Name, &resp.Diagnostics, "Group name")
	ValidateNoSurroundingWhitespace(data.Name, &resp.Diagnostics, "Group name")
	ValidateBranch(data.Branch, &resp.Diagnostics, "branch")
	ValidateNoSurroundingWhitespace(data.Branch, &resp.Diagnostics, "branch")
	ValidateGroupBranch(data.Branch, &resp.Diagnostics, "branch")

	if r.client != nil && !r.isSaaS() {
		ValidateOwner(data.Owner, &resp.Diagnostics, path.Root("owner"))
	} else if r.isSaaS() && isSet(data.Owner) {
		resp.Diagnostics.AddWarning(
			"Owner Ignored on Secrets Manager, SaaS",
			"Secrets Manager, SaaS does not support 'owner' for groups, so it has no effect here and is not "+
				"applied. If this group already has an owner (e.g. assigned before this configuration started "+
				"managing it), that assignment is unaffected but is no longer managed by Terraform. Remove "+
				"'owner' from this configuration to silence this warning; it remains fully supported on "+
				"Self-Hosted and OSS.",
		)
	}
}

// ModifyPlan forces replacement when owner or annotations change on
// Self-Hosted/OSS, where neither can be updated in place. On SaaS neither
// forces replace: Update applies annotations changes in place, and owner is
// inert (the V2 Group model has no owner field), so an owner change flows
// into Update as a no-op.
//
// When the client isn't configured for this plan (e.g. an unresolved JWT),
// the backend is unknown, so an owner or annotations change is planned as an
// in-place update with a warning rather than a replacement: forcing replace
// would drop memberships and grants if the deployment turns out to be SaaS.
// On SaaS Update then applies it in place; on Self-Hosted/OSS Update fails
// without making any changes, and a plan with credentials available plans
// the replacement.
//
// This lives here rather than in attribute plan modifiers because
// the backend is per-provider-configuration: isSaaS() reads the client that
// Configure set on THIS instance for THIS plan RPC (Configure runs before
// ModifyPlan in the same PlanResourceChange call), so two aliases pointing at
// different environments each get the correct decision. An attribute plan
// modifier can't do this: its closure is captured in Schema(), which fwserver
// caches from a throwaway, never-Configured instance.
//
// The create/destroy and "unchanged" guards mirror RequiresReplaceIf in
// objectplanmodifier and mapplanmodifier, so on Self-Hosted/OSS null vs {} and
// unknown values count as changes exactly as they did before.
//
// owner and annotations are read individually rather than through
// GroupResourceModel, whose map[string]string can't hold the unknown values a
// plan may contain (e.g. an annotation set from another resource's attribute).
func (r *GroupResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Do not replace on resource creation or destroy.
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	var planOwner, stateOwner types.Object
	var planAnnotations, stateAnnotations types.Map
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("owner"), &planOwner)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("owner"), &stateOwner)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("annotations"), &planAnnotations)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("annotations"), &stateAnnotations)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ownerChanged := !planOwner.Equal(stateOwner)
	annotationsChanged := !planAnnotations.Equal(stateAnnotations)
	if (!ownerChanged && !annotationsChanged) || r.isSaaS() {
		return
	}

	if r.client == nil {
		resp.Diagnostics.AddWarning("Deployment Type Unknown at Plan Time", "The provider client is not configured during this plan (e.g. the JWT token is not yet known), so it can't be determined whether this is Secrets Manager, SaaS or a Self-Hosted/OSS deployment. The owner or annotations change is therefore planned as an in-place update. On Secrets Manager, SaaS it will be applied in place. On Self-Hosted and OSS the apply will fail without making any changes, because this resource must be replaced there; re-run the plan once the provider credentials are available so the replacement is planned.")
		return
	}

	if ownerChanged {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("owner"))
	}
	if annotationsChanged {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("annotations"))
	}
}

// isSaaS reports whether groups should be managed through the V2 Groups REST
// API rather than policy YAML. It returns false when the client is
// unavailable (e.g. an unresolved JWT during plan), so callers that must not
// assume Self-Hosted/OSS in that case (ModifyPlan) check r.client first.
func (r *GroupResource) isSaaS() bool {
	if r.client == nil {
		return false
	}
	return r.client.GetConfig().Environment == conjurapi.EnvironmentSaaS
}

func (r *GroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data GroupResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.isSaaS() {
		r.createV2(&data, resp)
	} else {
		r.createViaPolicy(&data, resp)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "created group resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// createV2 creates the group through the V2 Groups API. data is left as
// planned rather than refreshed from the response: annotations is not
// Computed, so any difference in the server's echo (e.g. {} for a null plan)
// would fail to apply with "inconsistent result after apply". The V2 Group
// model has no owner field - ValidateConfig only warns about owner on this
// backend, so a configured owner is silently not sent.
func (r *GroupResource) createV2(data *GroupResourceModel, resp *resource.CreateResponse) {
	if _, err := r.client.CreateGroup(toV2Group(data)); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create group: %s", serverErrorDetail(err)))
	}
}

// createViaPolicy creates the group by generating and applying Conjur policy YAML, the provider's pre-V2 behavior.
// The PATCH load is an upsert, so a group that already exists is adopted rather than rejected; that is only
// warned about, since Self-Hosted/OSS has no import to bring an existing group under management otherwise.
// The warning is best-effort: the existence check and the PATCH are not atomic, and Conjur has no create-if-absent
// policy load, so a group created by another writer (e.g. a concurrent apply from a separate state) in between is
// adopted without the warning.
func (r *GroupResource) createViaPolicy(data *GroupResourceModel, resp *resource.CreateResponse) {
	groupPolicy, err := r.generateGroupPolicy(data)
	if err != nil {
		resp.Diagnostics.AddError("Error Generating Policy", fmt.Sprintf("Could not generate group policy: %s", err))
		return
	}

	groupID := r.policyGroupRoleID(data)
	exists, err := r.client.RoleExists(groupID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading Conjur group", fmt.Sprintf("Unable to check if group %q already exists: %s", groupID, serverErrorDetail(err)))
		return
	}

	if err := policy.ApplyPolicy(r.client, groupPolicy, normalizeBranch(data.Branch.ValueString())); err != nil {
		resp.Diagnostics.AddError("Error Applying Policy", fmt.Sprintf("Could not apply group policy: %s", serverErrorDetail(err)))
		return
	}

	if exists {
		resp.Diagnostics.AddWarning("Existing Group Adopted", fmt.Sprintf("The group %q already existed in Conjur and is now managed by Terraform. Its owner and annotations may have been rewritten to match this configuration, and it will be deleted when this resource is destroyed. If this group is managed elsewhere, run 'terraform state rm' on this resource before removing it from the configuration, so the group is not deleted.", groupID))
	}
}

// Update applies annotations changes on SaaS (see GroupResource's doc
// comment). Removed keys are deleted one at a time, in sorted order; a key
// that is already gone (404) counts as removed. Then, only if a key was added
// or changed, the full planned set is PATCHed. An owner-only change makes no
// API calls, since the V2 Group model has no owner field.
//
// On failure, state is set to the prior state minus the keys already removed,
// so the next plan retries only what's left. The PATCH response is not used to
// refresh state, for the same reason as in createV2.
//
// On Self-Hosted/OSS name, branch, owner and annotations all force replace,
// so Update is only reached there when the change was planned without a
// configured client (see ModifyPlan). It must then fail without making any
// changes, so both cases return an error. The framework pre-seeds the
// response state with the prior state, so leaving it untouched without an
// error would surface as "inconsistent result after apply" instead.
func (r *GroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider Client Not Configured", "The Conjur provider client is not available during apply (e.g. the JWT token is still unknown), so the group can't be updated. No changes were made. Re-run the plan and apply once the provider credentials are available.")
		return
	}

	if !r.isSaaS() {
		resp.Diagnostics.AddError("Update Not Supported", "This resource does not support in-place updates. Please recreate the resource to apply changes.")
		return
	}

	var plan, state GroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	identifier := groupIdentifier(plan.Branch.ValueString(), plan.Name.ValueString())
	partial := state
	partial.Annotations = maps.Clone(state.Annotations)

	var alreadyAbsent []string
	var failure string
	for _, key := range annotationKeysToRemove(state.Annotations, plan.Annotations) {
		err := r.client.DeleteGroupAnnotation(identifier, key)
		if err != nil && !isNotFoundErr(err) {
			failure = fmt.Sprintf("Unable to remove annotation %q from group %q: %s", key, identifier, serverErrorDetail(err))
			break
		}
		if err != nil {
			alreadyAbsent = append(alreadyAbsent, key)
		}
		delete(partial.Annotations, key)
	}

	if len(alreadyAbsent) > 0 {
		resp.Diagnostics.AddWarning("Annotations Already Absent", fmt.Sprintf("The following annotations were already absent from group %q, so there was nothing to remove: %s. They may have been removed outside Terraform, or the group may no longer exist.", identifier, quotedList(alreadyAbsent)))
	}

	if failure == "" && annotationsNeedPatch(state.Annotations, plan.Annotations) {
		if _, err := r.client.UpdateGroup(toV2Group(&plan)); err != nil {
			failure = fmt.Sprintf("Unable to update annotations of group %q: %s", identifier, serverErrorDetail(err))
		}
	}

	if failure != "" {
		resp.Diagnostics.Append(resp.State.Set(ctx, &partial)...)
		resp.Diagnostics.AddError("Client Error", failure)
		return
	}

	tflog.Trace(ctx, "updated group resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// annotationKeysToRemove returns the keys in state that plan no longer has,
// sorted so the per-key deletes run in a deterministic order.
func annotationKeysToRemove(state, plan map[string]string) []string {
	var keys []string
	for k := range state {
		if _, ok := plan[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

// quotedList renders keys as a comma-separated list of quoted strings, e.g. "a", "b".
func quotedList(keys []string) string {
	quoted := make([]string, len(keys))
	for i, k := range keys {
		quoted[i] = fmt.Sprintf("%q", k)
	}
	return strings.Join(quoted, ", ")
}

// annotationsNeedPatch reports whether plan adds a key to state or changes an
// existing key's value. Removals alone don't need a PATCH: it can't express them.
func annotationsNeedPatch(state, plan map[string]string) bool {
	for k, v := range plan {
		if old, ok := state[k]; !ok || old != v {
			return true
		}
	}
	return false
}

func (r *GroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data GroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var removed bool
	if r.isSaaS() {
		removed = r.readV2(ctx, &data, resp)
	} else {
		removed = r.readPolicy(ctx, &data, resp)
	}
	if resp.Diagnostics.HasError() || removed {
		return
	}

	tflog.Trace(ctx, "read group resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// readV2 fetches the group from the V2 Groups API and refreshes annotations
// from the response (there is no owner field to refresh). Surrounding
// whitespace is trimmed from name and branch so state written by earlier
// provider versions, which trimmed before calling the API, converges to the
// stored group without a replacement. It reports whether the resource was
// removed from state because the group no longer exists.
func (r *GroupResource) readV2(ctx context.Context, data *GroupResourceModel, resp *resource.ReadResponse) bool {
	identifier := groupIdentifier(data.Branch.ValueString(), data.Name.ValueString())

	group, err := r.client.ReadGroup(identifier)
	if isNotFoundErr(err) {
		resp.Diagnostics.AddWarning("Group Not Found", fmt.Sprintf("The group %q was not found in Conjur and will be removed from the state. If you did not expect this, please check your Conjur instance to ensure the group exists and can be managed by the provider identity.", identifier))
		resp.State.RemoveResource(ctx)
		return true
	}
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read group %q: %s", identifier, serverErrorDetail(err)))
		return false
	}

	data.Name = types.StringValue(strings.TrimSpace(data.Name.ValueString()))
	data.Branch = types.StringValue(strings.TrimSpace(data.Branch.ValueString()))
	r.applyGroupResponse(group, data)
	return false
}

// readPolicy checks whether the group still exists using the V1 role lookup
// (the pre-V2 behavior); it can't read owner or annotations back, so state
// is otherwise left unchanged. It reports whether the resource was removed
// from state.
func (r *GroupResource) readPolicy(ctx context.Context, data *GroupResourceModel, resp *resource.ReadResponse) bool {
	groupID := r.policyGroupRoleID(data)
	exists, err := r.client.RoleExists(groupID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading Conjur group",
			fmt.Sprintf("Unable to check if group %q exists: %s", groupID, serverErrorDetail(err)),
		)
		return false
	}

	if !exists {
		resp.Diagnostics.AddWarning("Group Not Found", fmt.Sprintf("The group %q was not found in Conjur and will be removed from the state. If you did not expect this, please check your Conjur instance to ensure the group exists and can be managed by the provider identity.", groupID))
		resp.State.RemoveResource(ctx)
		return true
	}

	return false
}

// policyGroupRoleID returns the fully qualified role ID of the group on the policy backend, using the same
// normalized branch the policy is loaded into, so create, read and delete all address the same group.
func (r *GroupResource) policyGroupRoleID(data *GroupResourceModel) string {
	return fullyQualifiedID(r.client, "group", branchQualifiedID(normalizeBranch(data.Branch.ValueString()), data.Name.ValueString()))
}

func (r *GroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data GroupResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.isSaaS() {
		r.deleteV2(&data, resp)
	} else {
		r.deleteViaPolicy(&data, resp)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "deleted group resource")
}

// deleteV2 deletes the group through the V2 Groups API. A group that is already gone (404) counts as deleted.
func (r *GroupResource) deleteV2(data *GroupResourceModel, resp *resource.DeleteResponse) {
	identifier := groupIdentifier(data.Branch.ValueString(), data.Name.ValueString())
	err := r.client.DeleteGroup(identifier)
	if isNotFoundErr(err) {
		resp.Diagnostics.AddWarning("Group Already Absent", fmt.Sprintf("The group %q was not found in Conjur, so there was nothing to delete. It may have been deleted outside Terraform.", identifier))
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete group %q: %s", identifier, serverErrorDetail(err)))
	}
}

// deleteViaPolicy deletes the group by generating and applying Conjur policy
// YAML, the provider's pre-V2 behavior.
func (r *GroupResource) deleteViaPolicy(data *GroupResourceModel, resp *resource.DeleteResponse) {
	groupPolicy, err := r.generateGroupDeletionPolicy(data)
	if err != nil {
		resp.Diagnostics.AddError("Error Generating Deletion Policy", fmt.Sprintf("Could not generate group deletion policy: %s", err))
		return
	}

	if err := policy.ApplyPolicy(r.client, groupPolicy, normalizeBranch(data.Branch.ValueString())); err != nil {
		resp.Diagnostics.AddError("Error Applying Deletion Policy", fmt.Sprintf("Could not apply group deletion policy: %s", serverErrorDetail(err)))
	}
}

func (r *GroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}

	if !r.isSaaS() {
		resp.Diagnostics.AddError(
			"Import Not Supported",
			"Importing conjur_group is only supported when the provider is configured against Secrets Manager, "+
				"SaaS. Self-Hosted and OSS groups are managed via policy and cannot be reliably reconstructed "+
				"from an identifier alone; add the group to your Terraform configuration and run 'terraform apply' "+
				"instead.",
		)
		return
	}

	id := strings.Trim(req.ID, "/")
	if id == "" || !strings.Contains(id, "/") {
		resp.Diagnostics.AddError("Unexpected Import Identifier", "Expected format: <branch>/<name>, e.g. data/teams/admins")
		return
	}

	branch, name := splitParentAndName(id)
	if problem := groupImportIDProblem(branch, name); problem != "" {
		resp.Diagnostics.AddError("Unexpected Import Identifier", fmt.Sprintf("Expected format: <branch>/<name>, e.g. data/teams/admins. Got %q: %s.", req.ID, problem))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("branch"), normalizeBranch(branch))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}

// applyGroupResponse copies annotations from a V2 API response into data,
// including clearing them when the server has none, so a server-side change
// (e.g. all keys cleared outside Terraform) is reflected on the next Read
// instead of leaving stale state. A nil and an empty map are treated as the
// same: when neither side has any annotations, data keeps its existing
// representation, because Terraform distinguishes null from {} and swapping
// one for the other would show up as a spurious diff against config. Name and
// branch are left untouched: both are Required, non-Computed attributes
// dictated by config, and overwriting them with the server's copy risks a
// spurious replacement if the two differ only in leading/trailing slashes. owner
// is never touched here - the V2 Group model has no such field.
func (r *GroupResource) applyGroupResponse(g *conjurapi.Group, data *GroupResourceModel) {
	if len(g.Annotations) == 0 && len(data.Annotations) == 0 {
		return
	}
	data.Annotations = g.Annotations
}

// toV2Group builds the conjurapi.Group payload sent to the V2 Groups API on
// both create and update, normalizing branch the same way as groupIdentifier
// so the two call sites can't drift out of sync. name is sent as configured:
// ValidateConfig rejects surrounding whitespace, so there is nothing to trim.
func toV2Group(data *GroupResourceModel) conjurapi.Group {
	return conjurapi.Group{
		Name:        data.Name.ValueString(),
		Branch:      normalizeBranch(data.Branch.ValueString()),
		Annotations: data.Annotations,
	}
}

// groupIdentifier builds the "<branch>/<name>" identifier the V2 Groups API
// expects, normalizing branch so a leading/trailing "/" can't produce a
// malformed path segment or a mismatched identifier. name is trimmed because
// state written by earlier provider versions may still hold surrounding
// whitespace that was stripped before the group was created. Unlike
// branchQualifiedID (shared with conjur_host and conjur_secret, which have
// their own, different leading-slash conventions), the V2 Groups API always
// wants a fully normalized identifier.
func groupIdentifier(branch, name string) string {
	return branchQualifiedID(normalizeBranch(branch), strings.TrimSpace(name))
}

func (r *GroupResource) generateGroupPolicy(data *GroupResourceModel) (string, error) {
	group := conjurpolicy.Group{
		Id: data.Name.ValueString(),
	}

	owner, ownerDiags := ownerFromObject(data.Owner)
	if err := diagsToError(ownerDiags); err != nil {
		return "", err
	}
	if owner != nil {
		ownerKind, err := conjurpolicy.KindString(owner.Kind)
		if err != nil {
			return "", fmt.Errorf("invalid owner kind: %w", err)
		}
		group.Owner = conjurpolicy.ResourceRef{
			Kind: ownerKind,
			Id:   owner.Id,
		}
	}

	if len(data.Annotations) > 0 {
		annotations := make(map[string]any)
		for k, v := range data.Annotations {
			annotations[k] = v
		}
		group.Annotations = annotations
	}

	policyStatements := conjurpolicy.PolicyStatements{group}

	yamlBytes, err := yaml.Marshal(policyStatements)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy to YAML: %w", err)
	}

	return string(yamlBytes), nil
}

func (r *GroupResource) generateGroupDeletionPolicy(data *GroupResourceModel) (string, error) {
	deleteDto := conjurpolicy.Delete{
		Record: conjurpolicy.ResourceRef{
			Kind: conjurpolicy.KindGroup,
			Id:   data.Name.ValueString(),
		},
	}

	policyStatements := conjurpolicy.PolicyStatements{deleteDto}
	yamlBytes, err := yaml.Marshal(policyStatements)
	if err != nil {
		return "", fmt.Errorf("failed to marshal deletion policy to YAML: %w", err)
	}

	return string(yamlBytes), nil
}
