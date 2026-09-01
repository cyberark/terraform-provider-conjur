package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
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
		typeName:   "conjur_issuer",
		capability: CapabilityIssuersV1,
	}
}

type IssuerResource struct {
	typeName   string
	capability Capability
	client     api.ClientV2
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

type SecretRef struct {
	Id string `json:"id"`
}

type AWSIssuerData struct {
	AccessKeyIdSecretRef     SecretRef `json:"access_key_id_secret_ref"`
	SecretAccessKeySecretRef SecretRef `json:"secret_access_key_secret_ref"`
}

func (r *IssuerResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_issuer"
}

func (r *IssuerResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "CyberArk Secrets Manager issuer resource. Destroying this resource deletes only the issuer itself and leaves the referenced Secrets Manager secrets intact.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The issuer's name. Changing it forces a new issuer to be created.",
				Required:            true,
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

func (r *IssuerResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	clients, ok := configureConjurClient(req, resp, r.capability, r.typeName)
	if !ok {
		return
	}
	r.client = clients.conjurClient
}

func (r *IssuerResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data IssuerResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ValidateNonBlank(data.Id, &resp.Diagnostics, "Issuer ID")
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
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data IssuerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	aws := modelFromObject[AWSIssuerModel](ctx, data.AWS, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	// ValidateConfig skips inspecting aws when it's unknown at plan time; re-check the "exactly one
	// issuer type block" invariant here in case it resolved to null by apply, which would otherwise
	// send a type-less payload and surface as an opaque API error.
	if !r.validateIssuerType(aws, &resp.Diagnostics) {
		return
	}

	created, err := r.client.CreateIssuer(r.buildIssuerPayload(&data, aws))
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create issuer, got error: %s", err))
		return
	}

	if err := r.parseIssuerResponse(ctx, created, &data); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to parse create issuer response, got error: %s", err))
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
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read issuer, got error: %s", err))
		return
	}

	if err := r.parseIssuerResponse(ctx, issuer, &data); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to parse read issuer response, got error: %s", err))
		return
	}
	tflog.Trace(ctx, "read issuer resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IssuerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data IssuerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	aws := modelFromObject[AWSIssuerModel](ctx, data.AWS, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	// ValidateConfig skips inspecting aws when it's unknown at plan time; re-check the "exactly one
	// issuer type block" invariant here in case it resolved to null by apply. Otherwise, the PATCH
	// would omit Data, leaving stale credentials attached server-side while state drops them, which
	// Terraform reports as an "inconsistent result after apply" error.
	if !r.validateIssuerType(aws, &resp.Diagnostics) {
		return
	}

	updated, err := r.client.UpdateIssuer(data.Id.ValueString(), r.buildIssuerUpdatePayload(&data, aws))
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to update issuer, got error: %s", err))
		return
	}

	if err := r.parseIssuerResponse(ctx, updated, &data); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to parse update issuer response, got error: %s", err))
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
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete issuer, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "deleted issuer resource")
}

func (r *IssuerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// validateIssuerType enforces the "exactly one issuer type block" invariant at apply time, mirroring
// ValidateConfig's check for the case where aws was unknown at plan time and resolved to null. It
// reports true when the invariant holds, false (with a diagnostic added) otherwise.
func (r *IssuerResource) validateIssuerType(aws *AWSIssuerModel, diags *diag.Diagnostics) bool {
	if aws == nil {
		diags.AddError("Invalid issuer configuration", "Exactly one issuer type block must be specified (e.g., aws {}).")
		return false
	}
	return true
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

func (r *IssuerResource) parseIssuerResponse(ctx context.Context, issuer conjurapi.Issuer, data *IssuerResourceModel) error {
	data.Id = types.StringValue(issuer.ID)
	data.MaxTTL = types.Int32Value(int32(issuer.MaxTTL))
	data.CreatedAt = types.StringValue(issuer.CreatedAt)
	data.ModifiedAt = types.StringValue(issuer.ModifiedAt)
	if issuer.Type == "aws" {
		awsData, err := awsIssuerDataFromMap(issuer.Data)
		if err != nil {
			return err
		}
		obj, diags := types.ObjectValueFrom(ctx, awsIssuerAttrTypes, AWSIssuerModel{
			AccessKeyIdSecretRef:     types.StringValue(awsData.AccessKeyIdSecretRef.Id),
			SecretAccessKeySecretRef: types.StringValue(awsData.SecretAccessKeySecretRef.Id),
		})
		if diags.HasError() {
			return fmt.Errorf("building aws object value: %v", diags)
		}
		data.AWS = obj
	} else {
		// Only "aws" issuers are supported today. Rather than silently nulling data.AWS (which would
		// masquerade as a plan to convert the issuer), reject the unsupported type outright. The
		// capability is named IssuersV1 because more kinds are expected; this keeps behavior explicit
		// until they're added.
		return fmt.Errorf("unsupported issuer type %q: this provider version only supports \"aws\" issuers", issuer.Type)
	}
	return nil
}
