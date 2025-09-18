package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &ConjurAuthenticatorResource{}
var _ resource.ResourceWithImportState = &ConjurAuthenticatorResource{}

func NewConjurAuthenticatorResource() resource.Resource {
	return &ConjurAuthenticatorResource{}
}

// ConjurAuthenticatorResource defines the resource implementation.
type ConjurAuthenticatorResource struct {
	client *conjurapi.Client
}

// ConjurAuthenticatorResourceModel describes the resource data model.
type ConjurAuthenticatorResourceModel struct {
	Type        types.String                   `tfsdk:"type"`
	Name        types.String                   `tfsdk:"name"`
	Subtype     types.String                   `tfsdk:"subtype"`
	Enabled     types.Bool                     `tfsdk:"enabled"`
	Owner       *ConjurAuthenticatorOwnerModel `tfsdk:"owner"`
	Data        *ConjurAuthenticatorDataModel  `tfsdk:"data"`
	Annotations map[string]string              `tfsdk:"annotations"`
}

type ConjurAuthenticatorOwnerModel struct {
	Kind types.String `tfsdk:"kind"`
	ID   types.String `tfsdk:"id"`
}

type ConjurAuthenticatorDataModel struct {
	Audience   types.String                      `tfsdk:"audience"`
	JwksURI    types.String                      `tfsdk:"jwks_uri"`
	Issuer     types.String                      `tfsdk:"issuer"`
	CACert     types.String                      `tfsdk:"ca_cert"`
	PublicKeys types.String                      `tfsdk:"public_keys"`
	Identity   *ConjurAuthenticatorIdentityModel `tfsdk:"identity"`
}

type ConjurAuthenticatorIdentityModel struct {
	IdentityPath     types.String      `tfsdk:"identity_path"`
	TokenAppProperty types.String      `tfsdk:"token_app_property"`
	ClaimAliases     map[string]string `tfsdk:"claim_aliases"`
	EnforcedClaims   []string          `tfsdk:"enforced_claims"`
}

func (r *ConjurAuthenticatorResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_authenticator"
}

func (r *ConjurAuthenticatorResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Conjur authenticator resource",

		Attributes: map[string]schema.Attribute{
			"type": schema.StringAttribute{
				MarkdownDescription: "The authenticator type (e.g., jwt, ldap, oidc)",
				Required:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the authenticator",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"subtype": schema.StringAttribute{
				MarkdownDescription: "Authenticator subtype (e.g., github)",
				Optional:            true,
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the authenticator is enabled",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"annotations": schema.MapAttribute{
				MarkdownDescription: "Key-value annotations for the authenticator",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"owner": schema.SingleNestedAttribute{
				MarkdownDescription: "Owner of the authenticator",
				Optional:            true,
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
			},
			"data": schema.SingleNestedAttribute{
				MarkdownDescription: "Authenticator configuration data",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"audience": schema.StringAttribute{
						MarkdownDescription: "JWT audience",
						Optional:            true,
					},
					"jwks_uri": schema.StringAttribute{
						MarkdownDescription: "JWKS URI",
						Optional:            true,
					},
					"issuer": schema.StringAttribute{
						Optional: true,
					},
					"ca_cert": schema.StringAttribute{
						MarkdownDescription: "CA certificate",
						Optional:            true,
					},
					"public_keys": schema.StringAttribute{
						MarkdownDescription: "Public keys",
						Optional:            true,
					},
					"identity": schema.SingleNestedAttribute{
						MarkdownDescription: "Identity configuration",
						Optional:            true,
						Attributes: map[string]schema.Attribute{
							"identity_path": schema.StringAttribute{
								MarkdownDescription: "Identity path",
								Optional:            true,
							},
							"token_app_property": schema.StringAttribute{
								MarkdownDescription: "Token app property",
								Optional:            true,
							},
							"claim_aliases": schema.MapAttribute{
								MarkdownDescription: "Claim aliases mapping",
								Optional:            true,
								ElementType:         types.StringType,
							},
							"enforced_claims": schema.ListAttribute{
								MarkdownDescription: "List of enforced claims",
								Optional:            true,
								ElementType:         types.StringType,
							},
						},
					},
				},
			},
		},
	}
}

func (r *ConjurAuthenticatorResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*conjurapi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *ConjurClient, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *ConjurAuthenticatorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConjurAuthenticatorResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	newAuthenticator, err := r.buildAuthenticatorPayload(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Authenticator Payload", fmt.Sprintf("Could not build authenticator payload: %s", err))
		return
	}

	_, err = r.client.V2().CreateAuthenticator(newAuthenticator)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create authenticator, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "created authenticator resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurAuthenticatorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConjurAuthenticatorResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	authenticatorResponse, err := r.client.V2().GetAuthenticator(data.Type.ValueString(), data.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read authenticator, got error: %s", err))
		return
	}

	err = r.parseAuthenticatorResponse(authenticatorResponse, &data)
	if err != nil {
		resp.Diagnostics.AddError("Error Parsing Authenticator Payload", fmt.Sprintf("Could not parse authenticator payload: %s", err))
		return
	}

	tflog.Trace(ctx, "read authenticator resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)

}

func (r *ConjurAuthenticatorResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ConjurAuthenticatorResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	authenticator, err := r.buildAuthenticatorPayload(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Authenticator Payload", fmt.Sprintf("Could not build authenticator payload: %s", err))
		return
	}

	err = r.client.V2().DeleteAuthenticator(authenticator.Type, authenticator.Name)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete existing authenticator for update, got error: %s", err))
		return
	}

	_, err = r.client.V2().CreateAuthenticator(authenticator)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create authenticator, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "updated authenticator resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurAuthenticatorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConjurAuthenticatorResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.V2().DeleteAuthenticator(data.Type.ValueString(), data.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete authenticator, got error: %s", err))
		return
	}

	tflog.Trace(ctx, "deleted authenticator resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurAuthenticatorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			"Expected format: <type>:<name>",
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("type"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[1])...)
}

// buildAuthenticatorPayload maps the resource model to an API payload
func (r *ConjurAuthenticatorResource) buildAuthenticatorPayload(data *ConjurAuthenticatorResourceModel) (*conjurapi.AuthenticatorBase, error) {

	// Initialize with required fields
	authenticator := conjurapi.AuthenticatorBase{
		Type: data.Type.ValueString(),
		Name: data.Name.ValueString(),
	}

	// Only include optional fields if they have values
	if !data.Subtype.IsNull() && !data.Subtype.IsUnknown() {
		authenticator.Subtype = data.Subtype.ValueStringPointer()
	}

	if !data.Enabled.IsNull() && !data.Enabled.IsUnknown() {
		authenticator.Enabled = data.Enabled.ValueBoolPointer()
	}

	if data.Owner != nil {
		authenticator.Owner = &conjurapi.AuthOwner{
			Kind: data.Owner.Kind.ValueString(),
			ID:   data.Owner.ID.ValueString(),
		}
	}

	if data.Data != nil {
		dataPayload := make(map[string]interface{})

		if !data.Data.Audience.IsNull() && !data.Data.Audience.IsUnknown() {
			dataPayload["audience"] = data.Data.Audience.ValueString()
		}
		if !data.Data.JwksURI.IsNull() && !data.Data.JwksURI.IsUnknown() {
			dataPayload["jwks_uri"] = data.Data.JwksURI.ValueString()
		}
		if !data.Data.Issuer.IsNull() && !data.Data.Issuer.IsUnknown() {
			dataPayload["issuer"] = data.Data.Issuer.ValueString()
		}
		if !data.Data.CACert.IsNull() && !data.Data.CACert.IsUnknown() {
			dataPayload["ca_cert"] = data.Data.CACert.ValueString()
		}
		if !data.Data.PublicKeys.IsNull() && !data.Data.PublicKeys.IsUnknown() {
			var publicKeysObj interface{}
			jsonStr := data.Data.PublicKeys.ValueString()
			err := json.Unmarshal([]byte(jsonStr), &publicKeysObj)
			if err != nil {
				return nil, fmt.Errorf("invalid JSON in public_keys: %w", err)
			}
			dataPayload["public_keys"] = publicKeysObj
		}

		if data.Data.Identity != nil {
			identityPayload := make(map[string]interface{})

			if !data.Data.Identity.IdentityPath.IsNull() && !data.Data.Identity.IdentityPath.IsUnknown() {
				identityPayload["identity_path"] = data.Data.Identity.IdentityPath.ValueString()
			}
			if !data.Data.Identity.TokenAppProperty.IsNull() && !data.Data.Identity.TokenAppProperty.IsUnknown() {
				identityPayload["token_app_property"] = data.Data.Identity.TokenAppProperty.ValueString()
			}
			if len(data.Data.Identity.ClaimAliases) > 0 {
				identityPayload["claim_aliases"] = data.Data.Identity.ClaimAliases
			}
			if len(data.Data.Identity.EnforcedClaims) > 0 {
				identityPayload["enforced_claims"] = data.Data.Identity.EnforcedClaims
			}

			if len(identityPayload) > 0 {
				dataPayload["identity"] = identityPayload
			}
		}

		if len(dataPayload) > 0 {
			authenticator.Data = dataPayload
		}
	}

	if len(data.Annotations) > 0 {
		authenticator.Annotations = data.Annotations
	}

	return &authenticator, nil
}

// parseAuthenticatorResponse maps the API response to the resource model
func (r *ConjurAuthenticatorResource) parseAuthenticatorResponse(authenticator *conjurapi.AuthenticatorResponse, data *ConjurAuthenticatorResourceModel) error {
	data.Type = types.StringValue(authenticator.Type)
	data.Name = types.StringValue(authenticator.Name)
	if authenticator.Subtype != nil {
		data.Subtype = types.StringValue(*authenticator.Subtype)
	} else {
		data.Subtype = types.StringNull()
	}
	if authenticator.Enabled != nil {
		data.Enabled = types.BoolValue(*authenticator.Enabled)
	} else {
		data.Enabled = types.BoolNull()
	}
	if authenticator.Owner != nil {
		data.Owner = &ConjurAuthenticatorOwnerModel{
			Kind: types.StringValue(authenticator.Owner.Kind),
			ID:   types.StringValue(authenticator.Owner.ID),
		}
	} else {
		data.Owner = nil
	}
	if authenticator.Data != nil {
		dataModel := ConjurAuthenticatorDataModel{}

		if audience, ok := authenticator.Data["audience"].(string); ok {
			dataModel.Audience = types.StringValue(audience)
		} else {
			dataModel.Audience = types.StringNull()
		}
		if jwksURI, ok := authenticator.Data["jwks_uri"].(string); ok {
			dataModel.JwksURI = types.StringValue(jwksURI)
		} else {
			dataModel.JwksURI = types.StringNull()
		}
		if issuer, ok := authenticator.Data["issuer"].(string); ok {
			dataModel.Issuer = types.StringValue(issuer)
		} else {
			dataModel.Issuer = types.StringNull()
		}
		if caCert, ok := authenticator.Data["ca_cert"].(string); ok {
			dataModel.CACert = types.StringValue(caCert)
		} else {
			dataModel.CACert = types.StringNull()
		}
		if publicKeys, ok := authenticator.Data["public_keys"]; ok {
			publicKeysJSON, err := json.Marshal(publicKeys)
			if err != nil {
				return fmt.Errorf("invalid JSON in public_keys: %w", err)
			}
			dataModel.PublicKeys = types.StringValue(string(publicKeysJSON))
		} else {
			dataModel.PublicKeys = types.StringNull()
		}

		if identityRaw, ok := authenticator.Data["identity"].(map[string]interface{}); ok {
			identityModel := ConjurAuthenticatorIdentityModel{}

			if identityPath, ok := identityRaw["identity_path"].(string); ok {
				identityModel.IdentityPath = types.StringValue(identityPath)
			} else {
				identityModel.IdentityPath = types.StringNull()
			}
			if tokenAppProperty, ok := identityRaw["token_app_property"].(string); ok {
				identityModel.TokenAppProperty = types.StringValue(tokenAppProperty)
			} else {
				identityModel.TokenAppProperty = types.StringNull()
			}
			if claimAliases, ok := identityRaw["claim_aliases"].(map[string]interface{}); ok {
				stringMap := make(map[string]string)
				for k, v := range claimAliases {
					if strVal, ok := v.(string); ok {
						stringMap[k] = strVal
					}
				}
				identityModel.ClaimAliases = stringMap
			} else {
				identityModel.ClaimAliases = nil
			}
			if enforcedClaims, ok := identityRaw["enforced_claims"].([]interface{}); ok {
				stringList := make([]string, 0, len(enforcedClaims))
				for _, v := range enforcedClaims {
					if strVal, ok := v.(string); ok {
						stringList = append(stringList, strVal)
					}
				}
				identityModel.EnforcedClaims = stringList
			} else {
				identityModel.EnforcedClaims = nil
			}
			dataModel.Identity = &identityModel
		} else {
			dataModel.Identity = nil
		}
		data.Data = &dataModel
	} else {
		data.Data = nil
	}
	data.Annotations = authenticator.Annotations

	return nil
}
