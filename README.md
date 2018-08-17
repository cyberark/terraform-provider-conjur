# terraform-provider-conjur

Terraform Conjur provider

[![GitHub release](https://img.shields.io/github/release/cyberark/terraform-provider-conjur.svg)](https://github.com/cyberark/terraform-provider-conjur/releases/latest)

[![pipeline status](https://gitlab.com/cyberark/terraform-provider-conjur/badges/master/pipeline.svg)](https://gitlab.com/cyberark/terraform-provider-conjur/pipelines)
[![Maintainability](https://api.codeclimate.com/v1/badges/e9fc0a2de573aa189a3c/maintainability)](https://codeclimate.com/github/cyberark/terraform-provider-conjur/maintainability)

---

## Usage

### Provider configuration

With embedded values:

**main.tf**

```
provider "conjur" {
  appliance_url = "http://localhost:8080"
  account = "quick-start"
  login = "admin"
  api_key = "3ahcddy39rcxzh3ggac4cwk3j2r8pqwdg33059y835ys2rh2kzs2a"
  ssl_cert_path = "/etc/conjur.pem"
}
```

With environment variables:

```
export CONJUR_APPLIANCE_URL="https://localhost:8443"
export CONJUR_ACCOUNT="quick-start"
export CONJUR_AUTHN_LOGIN="admin"
export CONJUR_AUTHN_API_KEY="3ahcddy39rcxzh3ggac4cwk3j2r8pqwdg33059y835ys2rh2kzs2a"
export CONJUR_CERT_FILE="/etc/conjur.pem"
```

**main.tf**

```
provider "conjur" {}
```

### Fetch secrets

**main.tf**

```
# ... provider configuration above

data "conjur_secret" "dbpass" {
  name = "my/shiny/dbpass"
}

output "dbpass_output" {
  value = "${data.conjur_secret.dbpass.value}"
  sensitive = true  # toggle this off to view value
}
```

Secrets like `data.conjur_secret.dbpass.value` can be used in any Terraform resources.

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

**variables.tf**

```
variable "access_key" {}
variable "secret_key" {}
```

**secrets.yml**

```
TF_VAR_access_key: !var aws/dev/sys_powerful/access_key_id
TF_VAR_secret_key: !var aws/dev/sys_powerful/secret_access_key
```

Run Terraform with Summon:

```
summon terraform apply
```

---

## License

Copyright 2016-2018 CyberArk

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this software except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
