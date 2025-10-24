package provider

import (
	"context"
	"fmt"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &certificateIssueDataSource{}
	_ datasource.DataSourceWithConfigure = &certificateIssueDataSource{}
)

// Interfaces for easier mocking in tests
type certificateIssueClient interface {
	V2() certificateIssueV2Client
}

type certificateIssueV2Client interface {
	CertificateIssue(issuerName string, issue conjurapi.Issue) (*conjurapi.CertificateResponse, error)
}

type certificateIssueDataSource struct {
	client certificateIssueClient
}

func NewCertificateIssueDataSource() datasource.DataSource {
	return &certificateIssueDataSource{}
}

type certificateIssueDataSourceModel struct {
	IssuerName   types.String   `tfsdk:"issuer_name"`
	CommonName   types.String   `tfsdk:"common_name"`
	Organization types.String   `tfsdk:"organization"`
	OrgUnits     []types.String `tfsdk:"org_units"`
	Locality     types.String   `tfsdk:"locality"`
	State        types.String   `tfsdk:"state"`
	Country      types.String   `tfsdk:"country"`
	KeyType      types.String   `tfsdk:"key_type"`
	TTL          types.String   `tfsdk:"ttl"`
	Zone         types.String   `tfsdk:"zone"`

	DNSNames       []types.String `tfsdk:"dns_names"`
	IPAddresses    []types.String `tfsdk:"ip_addresses"`
	EmailAddresses []types.String `tfsdk:"email_addresses"`
	Uris           []types.String `tfsdk:"uris"`

	Certificate types.String   `tfsdk:"certificate"`
	Chain       []types.String `tfsdk:"chain"`
	PrivateKey  types.String   `tfsdk:"private_key"`
}

func (d *certificateIssueDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate_issue"
}

func (d *certificateIssueDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Issue a certificate using a Conjur certificate issuer.",
		Attributes: map[string]schema.Attribute{
			"issuer_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the Conjur issuer to use.",
			},
			"common_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Common Name for the issued certificate.",
			},
			"organization": schema.StringAttribute{Optional: true},
			"org_units":    schema.ListAttribute{ElementType: types.StringType, Optional: true},
			"locality":     schema.StringAttribute{Optional: true},
			"state":        schema.StringAttribute{Optional: true},
			"country":      schema.StringAttribute{Optional: true},
			"key_type":     schema.StringAttribute{Optional: true, MarkdownDescription: "Key type (e.g., RSA or ECDSA)."},
			"ttl":          schema.StringAttribute{Optional: true, MarkdownDescription: "Time-to-live for the certificate (e.g., '24h')."},
			"zone":         schema.StringAttribute{Optional: true},
			"dns_names":    schema.ListAttribute{ElementType: types.StringType, Optional: true},
			"ip_addresses": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"email_addresses": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"uris": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},

			// Outputs
			"certificate": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The issued certificate in PEM format.",
			},
			"chain": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Certificate chain returned by the issuer.",
			},
			"private_key": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Private key in PEM format.",
			},
		},
	}
}

func (d *certificateIssueDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(certificateIssueClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Provider Data Type",
			fmt.Sprintf("Expected *conjurapi.Client, got: %T", req.ProviderData),
		)
		return
	}
	d.client = client
}

func (d *certificateIssueDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data certificateIssueDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	subject := conjurapi.IssuerSubject{
		CommonName:   data.CommonName.ValueString(),
		Organization: data.Organization.ValueString(),
		Locality:     data.Locality.ValueString(),
		State:        data.State.ValueString(),
		Country:      data.Country.ValueString(),
	}
	for _, ou := range data.OrgUnits {
		subject.OrgUnits = append(subject.OrgUnits, ou.ValueString())
	}

	alt := conjurapi.AltNames{}
	for _, v := range data.DNSNames {
		alt.DNSNames = append(alt.DNSNames, v.ValueString())
	}
	for _, v := range data.IPAddresses {
		alt.IPAddresses = append(alt.IPAddresses, v.ValueString())
	}
	for _, v := range data.EmailAddresses {
		alt.EMailAddresses = append(alt.EMailAddresses, v.ValueString())
	}
	for _, v := range data.Uris {
		alt.Uris = append(alt.Uris, v.ValueString())
	}

	reqBody := conjurapi.Issue{
		Subject:  subject,
		KeyType:  data.KeyType.ValueString(),
		AltNames: alt,
		TTL:      data.TTL.ValueString(),
		Zone:     data.Zone.ValueString(),
	}

	tflog.Info(ctx, "Issuing certificate via Secrets Manager", map[string]interface{}{
		"issuer_name": data.IssuerName.ValueString(),
		"common_name": data.CommonName.ValueString(),
	})

	respObj, err := d.client.V2().CertificateIssue(data.IssuerName.ValueString(), reqBody)
	if err != nil {
		resp.Diagnostics.AddError("Error issuing certificate", err.Error())
		return
	}

	data.Certificate = types.StringValue(respObj.Certificate)
	data.PrivateKey = types.StringValue(respObj.PrivateKey)
	data.Chain = make([]types.String, len(respObj.Chain))
	for i, c := range respObj.Chain {
		data.Chain[i] = types.StringValue(c)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
