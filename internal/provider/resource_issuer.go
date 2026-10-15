package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &IssuerResource{}
	_ resource.ResourceWithImportState    = &IssuerResource{}
	_ resource.ResourceWithConfigure      = &IssuerResource{}
	_ resource.ResourceWithValidateConfig = &IssuerResource{}
	_ resource.ResourceWithModifyPlan     = &IssuerResource{}
)

func NewIssuerResource() resource.Resource {
	return &IssuerResource{
		resourceBase[api.ClientV2]{
			conjurComponent(
				"conjur_issuer",
				CapabilityIssuersV1,
			),
		},
	}
}

type IssuerResource struct {
	resourceBase[api.ClientV2]
}

type IssuerResourceModel struct {
	Id         types.String `tfsdk:"id"`
	MaxTTL     types.Int32  `tfsdk:"max_ttl"`
	AWS        types.Object `tfsdk:"aws"`
	CreatedAt  types.String `tfsdk:"created_at"`
	ModifiedAt types.String `tfsdk:"modified_at"`
}

type AWSIssuerModel struct {
	AccessKeyIdSecretRef     types.String `tfsdk:"access_key_id_secret_ref"`
	SecretAccessKeySecretRef types.String `tfsdk:"secret_access_key_secret_ref"`
}

// awsIssuerAttrTypes mirrors the schema of the "aws" SingleNestedAttribute. Modeling the value as
// types.Object (rather than *AWSIssuerModel) lets "aws" carry an unknown-at-plan-time object, e.g.
// when it's built from a conditional referencing not-yet-created resources.
var awsIssuerAttrTypes = map[string]attr.Type{
	"access_key_id_secret_ref":     types.StringType,
	"secret_access_key_secret_ref": types.StringType,
}

// issuerIDPattern is the set of characters the Conjur API accepts in an issuer ID. The SDK escapes the
// ID with url.QueryEscape rather than path escaping, so restricting it also rules out dot segments
// ("." / "..") that a normalizing proxy would resolve to the issuers collection or its parent.
var issuerIDPattern = regexp.MustCompile(`^[A-Za-z0-9+_-]+$`)

const issuerIDPatternDescription = "must contain only the characters A-Z, a-z, 0-9, +, - and _"

type SecretRef struct {
	Id string `json:"id"`
}

type AWSIssuerData struct {
	AccessKeyIdSecretRef     SecretRef `json:"access_key_id_secret_ref"`
	SecretAccessKeySecretRef SecretRef `json:"secret_access_key_secret_ref"`
}

func (r *IssuerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "CyberArk Secrets Manager issuer resource. Destroying this resource deletes only the issuer itself and leaves the referenced Secrets Manager secrets intact.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The issuer's name. May contain only the characters `A-Z`, `a-z`, `0-9`, `+`, `-` and `_`. Changing it forces a new issuer to be created.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(issuerIDPattern, issuerIDPatternDescription),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"max_ttl": schema.Int32Attribute{
				MarkdownDescription: "The maximum time-to-live, in seconds, of dynamic secrets created with this issuer. Must be between `900` and `43200`, and cannot be decreased once the issuer exists.",
				Required:            true,
			},
			"aws": schema.SingleNestedAttribute{
				MarkdownDescription: "Configuration for an AWS issuer. Exactly one issuer type block must be specified at a time.",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"access_key_id_secret_ref": schema.StringAttribute{
						MarkdownDescription: "The identifier of the Secrets Manager secret that holds the AWS access key ID.",
						Required:            true,
					},
					"secret_access_key_secret_ref": schema.StringAttribute{
						MarkdownDescription: "The identifier of the Secrets Manager secret that holds the AWS secret access key.",
						Required:            true,
					},
				},
			},
			"created_at": schema.StringAttribute{
				MarkdownDescription: "The timestamp at which the issuer was created.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_at": schema.StringAttribute{
				MarkdownDescription: "The timestamp at which the issuer was last modified.",
				Computed:            true,
			},
		},
	}
}

func (r *IssuerResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data IssuerResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ValidateIntInRange(data.MaxTTL, &resp.Diagnostics, "Max TTL", 900, 43_200)

	configured := 0
	if !data.AWS.IsNull() {
		configured++
		// Only inspect inner refs when the object is fully known. An unknown object (built from a
		// conditional over not-yet-created resources) is validated at apply time instead.
		if !data.AWS.IsUnknown() {
			aws := modelFromObject[AWSIssuerModel](ctx, data.AWS, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
			ValidateNonBlank(aws.AccessKeyIdSecretRef, &resp.Diagnostics, "AWS access key ID secret ref")
			ValidateNonBlank(aws.SecretAccessKeySecretRef, &resp.Diagnostics, "AWS secret access key secret ref")
		}
	}
	if configured != 1 {
		resp.Diagnostics.AddError("Invalid issuer configuration", "Exactly one issuer type block must be specified (e.g., aws {}).")
	}
}

func (r *IssuerResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var plan IssuerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state IssuerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Issuer will be recreated if ID is different, so the MaxTTL validation shouldn't be carried out.
	// Unknown MaxTTL at plan time means that the validation should be carried out at apply time.
	if !plan.Id.Equal(state.Id) || plan.MaxTTL.IsUnknown() {
		return
	}
	if plan.MaxTTL.ValueInt32() < state.MaxTTL.ValueInt32() {
		resp.Diagnostics.AddAttributeError(path.Root("max_ttl"), "Invalid max_ttl", fmt.Sprintf("max_ttl cannot be decreased (current: %d, new: %d).", state.MaxTTL.ValueInt32(), plan.MaxTTL.ValueInt32()))
	}
}

func (r *IssuerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	data, aws, ok := r.planForApply(ctx, req.Plan, &resp.Diagnostics)
	if !ok {
		return
	}

	created, err := r.client.CreateIssuer(r.buildIssuerPayload(&data, aws))
	if err != nil {
		if isResponseDecodeErr(err) {
			addIssuerCreatedButUnparsedError(&resp.Diagnostics, data.Id.ValueString(), err)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create issuer, got error: %s", serverErrorDetail(err)))
		return
	}

	if err := r.parseIssuerResponse(ctx, created, &data); err != nil {
		addIssuerCreatedButUnparsedError(&resp.Diagnostics, data.Id.ValueString(), err)
		return
	}
	tflog.Trace(ctx, "created issuer resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IssuerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data IssuerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	issuer, err := r.client.Issuer(data.Id.ValueString())
	if err != nil {
		if isNotFoundErr(err) {
			resp.Diagnostics.AddWarning("Issuer Not Found", fmt.Sprintf("The issuer %q was not found in Conjur and will be removed from the state. If you did not expect this, please check your Conjur instance to ensure the issuer exists and can be managed by the provider identity.", data.Id.ValueString()))
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read issuer, got error: %s", serverErrorDetail(err)))
		return
	}

	if err := r.parseIssuerResponse(ctx, issuer, &data); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to parse read issuer response, got error: %s", sanitizeServerText(err.Error())))
		return
	}
	tflog.Trace(ctx, "read issuer resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IssuerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	data, aws, ok := r.planForApply(ctx, req.Plan, &resp.Diagnostics)
	if !ok {
		return
	}
	var state IssuerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// ModifyPlan skips this check when max_ttl is unknown at plan time.
	if data.MaxTTL.ValueInt32() < state.MaxTTL.ValueInt32() {
		resp.Diagnostics.AddAttributeError(path.Root("max_ttl"), "Invalid max_ttl", fmt.Sprintf("max_ttl cannot be decreased (current: %d, new: %d).", state.MaxTTL.ValueInt32(), data.MaxTTL.ValueInt32()))
		return
	}

	updated, err := r.client.UpdateIssuer(data.Id.ValueString(), r.buildIssuerUpdatePayload(&data, aws))
	if err != nil {
		if isResponseDecodeErr(err) {
			addIssuerUpdatedButUnparsedError(&resp.Diagnostics, data.Id.ValueString(), err)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to update issuer, got error: %s", serverErrorDetail(err)))
		return
	}

	if err := r.parseIssuerResponse(ctx, updated, &data); err != nil {
		addIssuerUpdatedButUnparsedError(&resp.Diagnostics, data.Id.ValueString(), err)
		return
	}
	tflog.Trace(ctx, "updated issuer resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IssuerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data IssuerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// keepSecrets=true so destroying the issuer never cascades into deleting the referenced Secrets Manager secrets, which Terraform may own/manage independently.
	err := r.client.DeleteIssuer(data.Id.ValueString(), true)
	if err != nil {
		if isNotFoundErr(err) {
			resp.Diagnostics.AddWarning("Issuer Not Found", fmt.Sprintf("The issuer %q was not found in Conjur anymore, likely because it was already deleted out-of-band, and will be removed from the state.", data.Id.ValueString()))
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete issuer, got error: %s", serverErrorDetail(err)))
		return
	}

	tflog.Trace(ctx, "deleted issuer resource")
}

func (r *IssuerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !issuerIDPattern.MatchString(req.ID) {
		resp.Diagnostics.AddError("Invalid import ID", fmt.Sprintf("The issuer ID %q %s.", req.ID, issuerIDPatternDescription))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// planForApply performs the steps shared by Create and Update: it checks that the client is
// configured, reads the plan, and re-validates id, max_ttl and the aws block. It reports false (with a diagnostic
// added) when the apply must not proceed.
func (r *IssuerResource) planForApply(ctx context.Context, plan tfsdk.Plan, diags *diag.Diagnostics) (IssuerResourceModel, *AWSIssuerModel, bool) {
	var data IssuerResourceModel
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(diags)
		return data, nil, false
	}
	diags.Append(plan.Get(ctx, &data)...)
	if diags.HasError() {
		return data, nil, false
	}

	// The id and max_ttl validators skip unknown values at plan time, so values that only resolved at
	// apply (e.g., references to not-yet-created resources) must be re-checked before reaching the API.
	if !issuerIDPattern.MatchString(data.Id.ValueString()) {
		diags.AddAttributeError(path.Root("id"), "Invalid issuer ID", fmt.Sprintf("The issuer ID %q %s.", data.Id.ValueString(), issuerIDPatternDescription))
	}
	ValidateIntInRange(data.MaxTTL, diags, "Max TTL", 900, 43_200)
	if diags.HasError() {
		return data, nil, false
	}

	aws := modelFromObject[AWSIssuerModel](ctx, data.AWS, diags)
	if diags.HasError() {
		return data, nil, false
	}
	// ValidateConfig skips inspecting aws when it's unknown at plan time; re-check here in case it
	// resolved to null or to blank secret refs by apply. A null aws would send a type-less payload on
	// create (an opaque API error) and, on update, omit Data from the PATCH, leaving stale credentials
	// attached server-side while state drops them ("inconsistent result after apply"); blank refs would
	// surface as a generic API error instead of the friendly validation message.
	if !r.validateIssuerType(aws, diags) {
		return data, nil, false
	}
	return data, aws, true
}

// addIssuerCreatedButUnparsedError reports a create that succeeded server-side but whose response
// couldn't be used. No state is saved, so the error tells the user to reconcile Secrets Manager
// instead of leaving the issuer silently untracked.
func addIssuerCreatedButUnparsedError(diags *diag.Diagnostics, id string, err error) {
	diags.AddError("Client Error", fmt.Sprintf("The create request for issuer %q succeeded, but the response could not be parsed: %s. The created issuer is not tracked in the Terraform state; check Secrets Manager and import or delete it before applying again.", id, sanitizeServerText(err.Error())))
}

// addIssuerUpdatedButUnparsedError reports an update that was applied server-side but whose response
// couldn't be used. The state keeps the prior values, so the error tells the user how to reconcile it
// instead of leaving it silently out of sync with Secrets Manager.
func addIssuerUpdatedButUnparsedError(diags *diag.Diagnostics, id string, err error) {
	diags.AddError("Client Error", fmt.Sprintf("The update request for issuer %q succeeded, but the response could not be parsed: %s. The Terraform state still holds the previous values; run `terraform apply -refresh-only` to reconcile it with Secrets Manager before applying again.", id, sanitizeServerText(err.Error())))
}

// isResponseDecodeErr reports whether err is a JSON decoding error. The SDK only decodes the body of a
// 2xx response, so such an error means the request was applied server-side.
func isResponseDecodeErr(err error) bool {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	return errors.As(err, &syntaxErr) || errors.As(err, &typeErr)
}

// validateIssuerType re-runs the apply-time invariants that ValidateConfig skips when aws is unknown
// at plan time: the "exactly one issuer type block" invariant (aws resolving to null) and the
// non-blank checks on the inner secret refs (which only become known at apply time). It reports true
// when the config is valid, false (with a diagnostic added) otherwise.
func (r *IssuerResource) validateIssuerType(aws *AWSIssuerModel, diags *diag.Diagnostics) bool {
	if aws == nil {
		diags.AddError("Invalid issuer configuration", "Exactly one issuer type block must be specified (e.g., aws {}).")
		return false
	}
	ValidateNonBlank(aws.AccessKeyIdSecretRef, diags, "AWS access key ID secret ref")
	ValidateNonBlank(aws.SecretAccessKeySecretRef, diags, "AWS secret access key secret ref")
	return !diags.HasError()
}

func (r *IssuerResource) buildIssuerPayload(data *IssuerResourceModel, aws *AWSIssuerModel) conjurapi.Issuer {
	issuer := conjurapi.Issuer{ID: data.Id.ValueString(), MaxTTL: int(data.MaxTTL.ValueInt32())}
	if aws != nil {
		issuer.Type = "aws"
		issuer.Data = map[string]any{
			"access_key_id_secret_ref":     SecretRef{Id: aws.AccessKeyIdSecretRef.ValueString()},
			"secret_access_key_secret_ref": SecretRef{Id: aws.SecretAccessKeySecretRef.ValueString()},
		}
	}
	return issuer
}

func (r *IssuerResource) buildIssuerUpdatePayload(data *IssuerResourceModel, aws *AWSIssuerModel) conjurapi.IssuerUpdate {
	maxTTL := int(data.MaxTTL.ValueInt32())
	update := conjurapi.IssuerUpdate{MaxTTL: &maxTTL}
	if aws != nil {
		update.Data = map[string]any{
			"access_key_id_secret_ref":     SecretRef{Id: aws.AccessKeyIdSecretRef.ValueString()},
			"secret_access_key_secret_ref": SecretRef{Id: aws.SecretAccessKeySecretRef.ValueString()},
		}
	}
	return update
}

// awsIssuerDataFromMap converts the generic map[string]any returned by the Conjur API into
// a typed AWSIssuerData by marshaling to JSON and back. This avoids manual map assertions and
// makes the expected wire shape (each secret ref is {"id": "..."}) explicit in the type system.
func awsIssuerDataFromMap(m map[string]any) (AWSIssuerData, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return AWSIssuerData{}, fmt.Errorf("marshal issuer data: %w", err)
	}
	var d AWSIssuerData
	if err := json.Unmarshal(b, &d); err != nil {
		return AWSIssuerData{}, fmt.Errorf("unmarshal issuer data: %w", err)
	}
	return d, nil
}

// parseIssuerResponse copies the server response into data. The response is validated first: data.Id
// must already hold the requested ID, and a response for a different (or empty) ID is rejected so it
// can't be written to state, where a later replacement would delete the server-chosen ID. data is
// left untouched when an error is returned.
func (r *IssuerResource) parseIssuerResponse(ctx context.Context, issuer conjurapi.Issuer, data *IssuerResourceModel) error {
	if issuer.ID != data.Id.ValueString() {
		return fmt.Errorf("the response is for issuer ID %s instead of the requested %q", formatServerIDs([]string{issuer.ID}), data.Id.ValueString())
	}
	if issuer.MaxTTL < math.MinInt32 || issuer.MaxTTL > math.MaxInt32 {
		return fmt.Errorf("max_ttl %d in the response is out of range", issuer.MaxTTL)
	}
	if issuer.Type != "aws" {
		return fmt.Errorf("unsupported issuer type %q: this provider version only supports \"aws\" issuers", issuer.Type)
	}
	awsData, err := awsIssuerDataFromMap(issuer.Data)
	if err != nil {
		return err
	}
	if awsData.AccessKeyIdSecretRef.Id == "" || awsData.SecretAccessKeySecretRef.Id == "" {
		return fmt.Errorf("the response is missing the AWS secret refs")
	}
	obj, diags := types.ObjectValueFrom(ctx, awsIssuerAttrTypes, AWSIssuerModel{
		AccessKeyIdSecretRef:     types.StringValue(awsData.AccessKeyIdSecretRef.Id),
		SecretAccessKeySecretRef: types.StringValue(awsData.SecretAccessKeySecretRef.Id),
	})
	if diags.HasError() {
		return fmt.Errorf("building aws object value: %v", diags)
	}
	data.Id = types.StringValue(issuer.ID)
	data.MaxTTL = types.Int32Value(int32(issuer.MaxTTL))
	data.CreatedAt = types.StringValue(issuer.CreatedAt)
	data.ModifiedAt = types.StringValue(issuer.ModifiedAt)
	data.AWS = obj
	return nil
}
