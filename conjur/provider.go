package conjur

import (
	"crypto/sha256"
	"encoding/hex"
	"log"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
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
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("CONJUR_APPLIANCE_URL", "http://localhost:8080"),
				Description: "Conjur endpoint URL",
			},
			"account": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("CONJUR_ACCOUNT", nil),
				Description: "Conjur account",
			},
			"login": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("CONJUR_AUTHN_LOGIN", nil),
				Description: "Conjur login",
			},
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("CONJUR_AUTHN_API_KEY", nil),
				Description: "Conjur API key",
			},
		},
		ConfigureFunc: providerConfig,
	}
}

func providerConfig(d *schema.ResourceData) (interface{}, error) {
	applianceURL := d.Get("appliance_url").(string)
	account := d.Get("account").(string)
	login := d.Get("login").(string)
	apiKey := d.Get("api_key").(string)

	config := conjurapi.Config{ApplianceURL: applianceURL, Account: account}

	loginPair := authn.LoginPair{Login: login, APIKey: apiKey}

	conjur, err := conjurapi.NewClientFromKey(config, loginPair)

	// _, err = conjur.Authenticate(loginPair)
	// if err != nil {
	// 	return nil, err
	// }

	return conjur, err
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
				Default:     "",
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
	// version := d.Get("version").(string)

	log.Printf("[DEBUG] Getting secret for name=%q version=%q", name, "latest")

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
