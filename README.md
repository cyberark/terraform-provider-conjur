# Terraform Provider Conjur
With the Help of Conjur Terraform Provider Plugin you can retrive secretes from Conjur.

## Certification level
[![](https://img.shields.io/badge/Certification%20Level-Certified-28A745?)](https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md)

This repository is a **Certified** level project. It's a community contributed project **reviewed and tested by CyberArk
and trusted to use with Conjur Open Source**. For more detailed information on our certification levels, see [our community guidelines](https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md#certified).

## Features
The following features are available with the Terraform Provider Plugin:
* Retrieve a single secret from the CyberArk Vault by specifying the path to the secret in the main.tf file or environment variable.

## Limitations

The Terraform Provider Plugin does not support creating, deleting, or updating secrets.

## Technical Requirements

|  Technology    |  Version |
|----------------|----------|
| GO             |   1.19   |
| Conjur OSS     |  1.9+    |
| Conjur Enterprise | 12.5  |
|ConjurSDK(GO)   |  0.10.1  |
|Conjur API      |  5.1     |

## Using terraform-provider-conjur with Conjur Open Source 

Are you using this project with [Conjur Open Source](https://github.com/cyberark/conjur)? Then we 
**strongly** recommend choosing the version of this project to use from the latest [Conjur OSS 
suite release](https://docs.conjur.org/Latest/en/Content/Overview/Conjur-OSS-Suite-Overview.html). 
Conjur maintainers perform additional testing on the suite release versions to ensure 
compatibility. When possible, upgrade your Conjur version to match the 
[latest suite release](https://docs.conjur.org/Latest/en/Content/ReleaseNotes/ConjurOSS-suite-RN.htm); 
when using integrations, choose the latest suite release that matches your Conjur version. For any 
questions, please contact us on [Discourse](https://discuss.cyberarkcommons.org/c/conjur/5).

## Prerequisites

The following are prerequisites to using the Terraform Provider Plugin.

### 1.Conjur setup

You need to Setup Conjur OSS locally. To setup Conjur OSS follow Conjur quickstart [Cyberark-Conjur-OSS](https://github.com/cyberark/conjur-quickstart)

### 2.Binaries 
The recommended way to install `terraform-provider-conjur` is to use the binary distributions from this project's
[GitHub Releases page](https://github.com/cyberark/terraform-provider-conjur/releases).
The packages are available for Linux, macOS and Windows.

Download and uncompress the latest release for your OS. This example uses the linux binary.

_Note: Replace `$VERSION` with the one you want to use. See [releases](https://github.com/cyberark/terraform-provider-conjur/releases)
page for available versions._

```sh-session
$ wget https://github.com/cyberark/terraform-provider-conjur/releases/download/v$VERSION/terraform-provider-conjur-$VERSION.tar.gz
$ tar -xvf terraform-provider-conjur-$VERSION.tar.gz
```

### 3.Homebrew (MacOS)

Add and update the [CyberArk Tools Homebrew tap](https://github.com/cyberark/homebrew-tools).

```sh-session
$ brew tap cyberark/tools
```

Install the provider and symlink it to Terraform's plugins directory. Symlinking is
necessary because [Homebrew is sandboxed and cannot write to your home directory](https://github.com/Homebrew/brew/issues/2986).

_Note: Replace `$VERSION` with the appropriate plugin version_

```sh-session
$ brew install terraform-provider-conjur

$ mkdir -p ~/.terraform.d/plugins/

$ # If Homebrew is installing somewhere other than `/usr/local/Cellar`, update the path as well.
$ ln -sf /usr/local/Cellar/terraform-provider-conjur/$VERSION/bin/terraform-provider-conjur_* \
    ~/.terraform.d/plugins/
```


If you already have an unversioned plugin that was previously downloaded, we first need
to remove it:
```sh-session
$ rm -f ~/.terraform.d/plugins/terraform-provider-conjur
```

Now copy the new binary to the Terraform's plugins folder. If this is your first plugin,
you will need to create the folder first.

```sh-session
$ mkdir -p ~/.terraform.d/plugins/
$ mv terraform-provider-conjur*/terraform-provider-conjur* ~/.terraform.d/plugins/
```

### 4.Compile from Source

If you wish to compile the provider from source code, you will first need Go installed
on your machine (version >=1.12 is required).

- Clone repository and go into the cloned directory
```sh-session
$ git clone https://github.com/cyberark/terraform-provider-conjur.git
$ cd terraform-provider-conjur
```
- Build the provider

```sh-session
$ mkdir -p ~/.terraform.d/plugins/terraform.example.com/cyberark/conjur/$VERSION/$platform_reference_in_go
$ # Example: platform_reference_in_go= darwin_amd64
$ # Note: If a static binary is required, use ./bin/build to create the executable
$ go build -o ~/.terraform.d/plugins/terraform.example.com/cyberark/conjur/$VERSION/$platform_reference_in_go/terraform-provider-conjur main.go
```
### Access from Terraform Registry
To use the Conjur Terraform Provider from the Terraform Registry:

In main.tf use registry.terraform.io/cyberark/conjur in source and replace version with the latest 

```sh-session
  terraform {
    required_providers {
      conjur = {
        source  = “registry.terraform.io/cyberark/conjur"
        version = "~> 0"
      }
    }
  }
  provider "conjur" {
    # All variables required for API Key, or Access Token authentication for Conjur Server. Refer to the Usage section for details.
  }
  data "conjur_secret" "dbpass" {
    name = "App/secretVar"
  }
  output "dbpass-to-output" {
    value = data.conjur_secret.dbpass.value
    sensitive = true
  }
  resource "local_file" "dbpass-to-file" {
    content = data.conjur_secret.dbpass.value
    filename = "${path.module}/../dbpass"
    file_permission = "0664"
  }
```

## Terrafrom Provider Usage

### Terraform Provider Workflow

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

## Provider configuration

The provider uses [conjur-api-go](https://github.com/cyberark/conjur-api-go) to load its
configuration. `conjur-api-go` can be configured using environment variables or using the
provider configuration in the `.tf` file.

### Option 1: Using environment variables for API Key Authentication 

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
### Option 2: Using environment variables for Access Token

```sh-session
export CONJUR_APPLIANCE_URL="https://conjur-server"
export CONJUR_ACCOUNT="myorg"
export CONJUR_AUTHN_TOKEN='{                       
  "protected": "eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiJhMjA1NmEwYTk4OWU5ZmEyMTVmMTQwNDlmZmIyMTc3N2QxN2QyMjlmNjc2MGI3YjJkNmZhY2UwMjQ2NmNkMDg0In0=",
  "payload": "eyJzdWIiOiJhZG1pbiIsImV4cCI6MTY2NjIwODQ4NiwiaWF0IjoxNjY2MjA4MDA2fQ==",
  "signature": "RiwpMqGfWKgN5fTWv9JY6XUmNGLrsrx6mIjLllt0NN8n2VoZCMqXOaoicSyan0w3aJ2Z-eAqi46-nko24qOYw6iybg7AIi9ws7G-d68IIgY0GMYbT4LGDb8GaHeN_y6eOpBMJHHyiHnaOeP5d8h47wLSzdPsaVzPpzd_lczJJSiUg11Qzh6_OxLAsF9Us80Ta-O320HSHg3IXzw-792eKUubAHPOUAY04xYhgoZ-vQbjQkOBmH8vAwnUQ10l_7w1A9upRDnulCK4KDl8VPAvBI1XhyiqIbxrcCZWfreVt0S6rvl3aTkeYbBPRh4vXpRP5KDKp6lznUi6dl75ZHfSbX_OHUNpiCZiY2wCRm69s2C4Ww5mvNq20fUvsf8tclVV"
}'
```

### Option 3: Using attributes

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
  
## Fetch secrets from Conjur
  
### Preface

An important thing to keep in mind is that by design Terraform state files can contain
sensitive data (which may include credentials fetched by this plugin). Use Terraform's
recommendations found [here](https://www.terraform.io/docs/state/sensitive-data.html) to
protect these values where possible.

### Example

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