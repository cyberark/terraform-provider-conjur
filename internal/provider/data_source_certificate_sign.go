package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/cyberark/conjur-api-go/conjurapi"
)

var (
	_ datasource.DataSource              = &certificateSignDataSource{}
	_ datasource.DataSourceWithConfigure = &certificateSignDataSource{}
)

// Interfaces for easier mocking in tests
type certificateSigner interface {
	CertificateSign(issuerName string, sign conjurapi.Sign) (*conjurapi.CertificateResponse, error)
}

func (c *conjurAPIWrapper) CertificateSign(issuerName string, sign conjurapi.Sign) (*conjurapi.CertificateResponse, error) {
	return c.client.V2().CertificateSign(issuerName, sign)
}

func NewCertificateSignDataSource() datasource.DataSource {
	return &certificateSignDataSource{}
}

type certificateSignDataSource struct {
	client certificateSigner
}

type certificateSignDataSourceModel struct {
	IssuerName types.String `tfsdk:"issuer_name"`
	Csr        types.String `tfsdk:"csr"`
	Zone       types.String `tfsdk:"zone"`
	TTL        types.String `tfsdk:"ttl"`

	Certificate types.String   `tfsdk:"certificate"`
	Chain       []types.String `tfsdk:"chain"`
	PrivateKey  types.String   `tfsdk:"private_key"`
}

func (d *certificateSignDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate_sign"
}

func (d *certificateSignDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Sign a certificate signing request (CSR) using a Secrets Manager certificate issuer.",
		Attributes: map[string]schema.Attribute{
			"issuer_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the Secrets Manager issuer to use for signing.",
			},
			"csr": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "PEM-encoded Certificate Signing Request to be signed.",
			},
			"zone": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional zone or policy path for the signing request.",
			},
			"ttl": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Time-to-live for the signed certificate (e.g., '24h').",
			},
			"certificate": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The signed certificate in PEM format.",
			},
			"chain": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Certificate chain returned by the issuer.",
			},
			"private_key": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Private key, if returned by the issuer (usually empty when signing a CSR).",
			},
		},
	}
}

func (d *certificateSignDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*conjurapi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Provider Data Type",
			fmt.Sprintf("Expected certificateSignClient, got: %T", req.ProviderData),
		)
		return
	}

	d.client = &conjurAPIWrapper{client}
}

func (d *certificateSignDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data certificateSignDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	signReq := conjurapi.Sign{
		Csr:  data.Csr.ValueString(),
		Zone: data.Zone.ValueString(),
		TTL:  data.TTL.ValueString(),
	}

	tflog.Info(ctx, "Signing CSR via Secrets Manager issuer", map[string]interface{}{
		"issuer_name": data.IssuerName.ValueString(),
	})

	signResp, err := d.client.CertificateSign(data.IssuerName.ValueString(), signReq)
	if err != nil {
		resp.Diagnostics.AddError("Error signing certificate", err.Error())
		return
	}

	data.Certificate = types.StringValue(signResp.Certificate)
	data.PrivateKey = types.StringValue(signResp.PrivateKey)
	data.Chain = make([]types.String, len(signResp.Chain))
	for i, c := range signResp.Chain {
		data.Chain[i] = types.StringValue(c)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
