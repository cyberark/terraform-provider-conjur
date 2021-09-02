# Conjur Provider

Terraform provider for [Conjur](https://www.conjur.org).

[![GitHub release](https://img.shields.io/github/release/cyberark/terraform-provider-conjur.svg)](https://github.com/cyberark/terraform-provider-conjur/releases/latest)

[![Maintainability](https://api.codeclimate.com/v1/badges/e9fc0a2de573aa189a3c/maintainability)](https://codeclimate.com/github/cyberark/terraform-provider-conjur/maintainability)

## Example Usage

### Workflow

Terraform can be run manually by users, but it is often run by machines.
Conjur supports authentication and authorization for both.

If you are logged into the [Conjur CLI](https://docs.conjur.org/Latest/en/Content/Tools/cli.html),
this provider will read your configuration.
If you have applied [Conjur machine identity](https://www.conjur.org/tutorials/policy/applications.html),
this provider will read the machine's configuration.

To access the values of secrets, the user/machine needs `execute` privilege
on the Conjur variables referenced in your Terraform manifests.

For more details, see the "Authentication" section
[on this page](https://docs.conjur.org/Latest/en/Content/Integrations/terraform.htm).

### Provider configuration

The provider uses [conjur-api-go](https://github.com/cyberark/conjur-api-go) to load its
configuration. `conjur-api-go` can be configured using environment variables or using the
provider configuration in the `.tf` file.

#### Using environment variables

```sh-session
export CONJUR_APPLIANCE_URL="https://conjur-server"
export CONJUR_ACCOUNT="myorg"
export CONJUR_AUTHN_LOGIN="admin"
export CONJUR_AUTHN_API_KEY="3ahcddy39rcxzh3ggac4cwk3j2r8pqwdg33059y835ys2rh2kzs2a"
export CONJUR_CERT_FILE="/etc/conjur.pem"
```

No other configuration is necessary in `main.tf`:

```
# main.tf
provider "conjur" {}
```

#### Using attributes

In addition, the provider can be configured using attributes in the
configuration. Attributes specified in `main.tf` override the configuration loaded by
`conjur-api-go`.

For example, with `conjur_api_key` and `conjur_ssl_cert`defined as
[input variables](https://www.terraform.io/docs/configuration/variables.html), this
type of configuration could be used:

```
# main.tf
variable "conjur_api_key" {}
variable "conjur_ssl_cert" {}
# If you have the certificate as a file, use this line instead
# variable "conjur_ssl_cert_path" {}

provider "conjur" {
  appliance_url = "http://conjur-server"
  ssl_cert = var.conjur_ssl_cert
  # If you have the certificate as a file, use this line instead
  # ssl_cert_path = var.conjur_ssl_cert_path

  account = "myorg"

  login = "admin"
  api_key = var.conjur_api_key
}
```

**Notes on precedence of configuration variable setting:**

- If both the environment variable **and** `.tf` configuration are present for a
  configuration setting, the `.tf` configuration takes precedence and the environment
  variable will be ignored.
- If the `.tf` configuration does not include **both** `login` and `api_key`, then
  environment variables will be used for these values instead.

### Fetch secrets

#### Preface

An important thing to keep in mind is that by design Terraform state files can contain
sensitive data (which may include credentials fetched by this plugin). Use Terraform's
recommendations found [here](https://www.terraform.io/docs/state/sensitive-data.html) to
protect these values where possible.

#### Example

_Note: If plan is being run manually, you will need to run `terraform init` first!_

```
# main.tf
# ... provider configuration above

data "conjur_secret" "dbpass" {
  name = "my/shiny/dbpass"
}

output "dbpass_output" {
  value = "${data.conjur_secret.dbpass.value}"
  
  # Must mark this output value as sensitive for Terraform v0.15+,
  # because it's derived from a Conjur variable value that is declared
  # as sensitive.
  sensitive = true
}
```

Secrets like `data.conjur_secret.dbpass.value` can be used in any Terraform resources.

View an example Terraform manifest and Conjur policies in the
[test/](test/) directory in this project.

---

## Alternate Workflow with Summon

If this Terraform provider does not fit your needs, you can also use
[summon](https://github.com/cyberark/summon) with the
[summon-conjur](https://github.com/cyberark/summon-conjur) provider
to provide secrets to Terraform via environment variables.
The user running `terraform` must already be authenticated with Conjur.

Terraform's [`TF_VAR_name` syntax](https://www.terraform.io/docs/configuration/environment-variables.html#tf_var_name)
allows a user to set Terraform variables via environment variables.
To use Terraform with Summon, prefix the environment variable names in secrets.yml with `TF_VAR_`.

### Example

```
# variables.tf
variable "access_key" {}
variable "secret_key" {}
```


```
# secrets.yml
TF_VAR_access_key: !var aws/dev/sys_powerful/access_key_id
TF_VAR_secret_key: !var aws/dev/sys_powerful/secret_access_key
```

Run Terraform with Summon:

```sh-session
$ summon terraform apply
```

---
