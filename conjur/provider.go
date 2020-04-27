package conjur

import (
	"crypto/sha256"
	"encoding/hex"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

// Provider implements Conjur as a terraform.ResourceProvider
func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		DataSourcesMap: map[string]*schema.Resource{
			"conjur_secret": dataSourceSecret(),
		},
		Schema: map[string]*schema.Schema{
			"appliance_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Conjur endpoint URL",
			},
			"account": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Conjur account",
			},
			"login": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Conjur login",
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Conjur API key",
			},
			"ssl_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Content of Conjur public SSL certificate",
			},
			"ssl_cert_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to Conjur public SSL certificate",
			},
		},
		ConfigureFunc: providerConfig,
	}
}

func providerConfig(d *schema.ResourceData) (interface{}, error) {

	config, err := conjurapi.LoadConfig()
	if err != nil {
		return nil, err
	}

	// If server info has been specified in the schema, use it. Otherwise,
	// assume the environment has everything needed.
	appliance_url := d.Get("appliance_url").(string)
	if appliance_url != "" {
		config.ApplianceURL = appliance_url
	}

	account := d.Get("account").(string)
	if account != "" {
		config.Account = account
	}

	ssl_cert := d.Get("ssl_cert").(string)
	if ssl_cert != "" {
		config.SSLCert = ssl_cert
	}

	ssl_cert_path := d.Get("ssl_cert_path").(string)
	if ssl_cert_path != "" {
		config.SSLCertPath = ssl_cert_path
	}

	// If creds have been specified in the schema, use them. Otherwise,
	// assume the environment has everything needed.
	login := d.Get("login").(string)
	apiKey := d.Get("api_key").(string)
	if login != "" && apiKey != "" {
		loginPair := authn.LoginPair{Login: login, APIKey: apiKey}

		return conjurapi.NewClientFromKey(config, loginPair)
	}

	return conjurapi.NewClientFromEnvironment(config)
}

func dataSourceSecret() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceSecretRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "name (path) of the secret",
			},
			"version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "version of the secret",
				Default:     "latest",
			},
			"value": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "value of the secret",
				Sensitive:   true,
			},
		},
	}
}

func dataSourceSecretRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*conjurapi.Client)

	name := d.Get("name").(string)
	version := d.Get("version").(string)

	log.Printf("[DEBUG] Getting secret for name=%q version=%q", name, version)

	secretValue, err := client.RetrieveSecret(name)

	if err != nil {
		return err
	}

	d.Set("value", string(secretValue))
	d.SetId(hash(string(secretValue)))

	return nil
}

func hash(s string) string {
	sha := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sha[:])
}
