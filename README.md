# terraform-provider-conjur

Terraform provider for [Conjur](https://www.conjur.org).

[![GitHub release](https://img.shields.io/github/release/cyberark/terraform-provider-conjur.svg)](https://github.com/cyberark/terraform-provider-conjur/releases/latest)


[![Maintainability](https://api.codeclimate.com/v1/badges/e9fc0a2de573aa189a3c/maintainability)](https://codeclimate.com/github/cyberark/terraform-provider-conjur/maintainability)

---

## Installation

### Using terraform-provider-conjur with Conjur Open Source 

Are you using this project with [Conjur Open Source](https://github.com/cyberark/conjur)? Then we 
**strongly** recommend choosing the version of this project to use from the latest [Conjur OSS 
suite release](https://docs.conjur.org/Latest/en/Content/Overview/Conjur-OSS-Suite-Overview.html). 
Conjur maintainers perform additional testing on the suite release versions to ensure 
compatibility. When possible, upgrade your Conjur version to match the 
[latest suite release](https://docs.conjur.org/Latest/en/Content/ReleaseNotes/ConjurOSS-suite-RN.htm); 
when using integrations, choose the latest suite release that matches your Conjur version. For any 
questions, please contact us on [Discourse](https://discuss.cyberarkcommons.org/c/conjur/5).

### Binaries (Recommended)
The recommended way to install `terraform-provider-conjur` is to use the binary distributions from this project's
[GitHub Releases page](https://github.com/cyberark/terraform-provider-conjur/releases).
The packages are available for Linux, macOS and Windows.

Download and uncompress the latest release for your OS. This example uses the linux binary.

_Note: Replace `$VERSION` with the one you want to use. See [releases](https://github.com/cyberark/terraform-provider-conjur/releases)
page for available versions._

```sh
$ wget https://github.com/cyberark/terraform-provider-conjur/releases/download/v$VERSION/terraform-provider-conjur-$VERSION-linux-amd64.tar.gz
$ tar -xvf terraform-provider-conjur*.tar.gz
```


If you already have an unversioned plugin that was previously downloaded, we first need
to remove it:
```sh
$ rm -f ~/.terraform.d/plugins/terraform-provider-conjur
```

Now copy the new binary to the Terraform's plugins folder. If this is your first plugin,
you will need to create the folder first.

```sh
$ mkdir -p ~/.terraform.d/plugins/
$ mv terraform-provider-conjur*/terraform-provider-conjur* ~/.terraform.d/plugins/
```

### Homebrew (MacOS)

Add and update the [CyberArk Tools Homebrew tap](https://github.com/cyberark/homebrew-tools).

```sh
$ brew tap cyberark/tools
```

Install the provider and symlink it to Terraform's plugins directory. Symlinking is
necessary because [Homebrew is sandboxed and cannot write to your home directory](https://github.com/Homebrew/brew/issues/2986).

_Note: Replace `$VERSION` with the appropriate plugin version_

```sh
$ brew install terraform-provider-conjur

$ mkdir -p ~/.terraform.d/plugins/

$ # If Homebrew is installing somewhere other than `/usr/local/Cellar`, update the path as well.
$ ln -sf /usr/local/Cellar/terraform-provider-conjur/$VERSION/bin/terraform-provider-conjur_* \
    ~/.terraform.d/plugins/
```

### Compile from Source

If you wish to compile the provider from source code, you will first need Go installed
on your machine (version >=1.12 is required).

- Clone repository and go into the cloned directory
```sh
$ git clone https://github.com/cyberark/terraform-provider-conjur.git
$ cd terraform-provider-conjur
```
- Build the provider

```sh
$ mkdir -p ~/.terraform.d/plugins/
$ # Note: If a static binary is required, use ./bin/build to create the executable
$ go build -o ~/.terraform.d/plugins/terraform-provider-conjur main.go
```

## Usage

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

```sh
export CONJUR_APPLIANCE_URL="https://conjur-server"
export CONJUR_ACCOUNT="myorg"
export CONJUR_AUTHN_LOGIN="admin"
export CONJUR_AUTHN_API_KEY="3ahcddy39rcxzh3ggac4cwk3j2r8pqwdg33059y835ys2rh2kzs2a"
export CONJUR_CERT_FILE="/etc/conjur.pem"
```

No other configuration is necessary in `main.tf`:

```terraform
# main.tf

# Configure the Conjur provider using the required_providers stanza
# required with Terraform 0.13 and beyond. You may optionally use version
# directive to prevent breaking changes occurring unannounced.
terraform {
  required_providers {
    conjur = {
      source  = "cyberark/conjur"
    }
  }
}

provider "conjur" {}
```

#### Using attributes

In addition, the provider can be configured using attributes in the
configuration. Attributes specified in `main.tf` override the configuration loaded by
`conjur-api-go`.

For example, with `conjur_api_key` and `conjur_ssl_cert`defined as
[input variables](https://www.terraform.io/docs/configuration/variables.html), this
type of configuration could be used:

```terraform
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

```terraform
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

### Update secrets

#### Preface

An important thing to keep in mind is that by design Terraform state files can contain
sensitive data (which may include credentials fetched by this plugin). Use Terraform's
recommendations found [here](https://www.terraform.io/docs/state/sensitive-data.html) to
protect these values where possible.

#### Example

_Note: If plan is being run manually, you will need to run `terraform init` first!_

```terraform
# main.tf
provider "conjur" {
  alias         = "read"
  appliance_url = "http://conjur-read-server"
}

provider "conjur" {
  alias         = "write"
  appliance_url = "http://conjur-write-server"
}

data "conjur_secret_update" "passwordupdate" {
  provider     = conjur.write
  name         = "my/shiny/dbpass"
  update_value = "shinynewdbvalue"
}

data "conjur_secret" "password" {
  depends_on   = [data.conjur_secret_update.passwordupdate]
  provider     = conjur.read
  name         = "my/shiny/dbpass"
}

```

Secrets like `data.conjur_secret.password.value` can be used in any Terraform resources.

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

```terraform
# variables.tf
variable "access_key" {}
variable "secret_key" {}
```


```yaml
# secrets.yml
TF_VAR_access_key: !var aws/dev/sys_powerful/access_key_id
TF_VAR_secret_key: !var aws/dev/sys_powerful/secret_access_key
```

Run Terraform with Summon:

```sh
$ summon terraform apply
```

---

## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and descriptions of our development workflows, please see our [contributing
guide][contrib].

[contrib]: CONTRIBUTING.md

## License

Copyright 2016-2022 CyberArk

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this software except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
