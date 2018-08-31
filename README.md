# terraform-provider-conjur

Terraform provider for [Conjur](https://www.conjur.org).

[![GitHub release](https://img.shields.io/github/release/cyberark/terraform-provider-conjur.svg)](https://github.com/cyberark/terraform-provider-conjur/releases/latest)

[![pipeline status](https://gitlab.com/cyberark/terraform-provider-conjur/badges/master/pipeline.svg)](https://gitlab.com/cyberark/terraform-provider-conjur/pipelines)
[![Maintainability](https://api.codeclimate.com/v1/badges/e9fc0a2de573aa189a3c/maintainability)](https://codeclimate.com/github/cyberark/terraform-provider-conjur/maintainability)

---

## Installation

### Binaries (Recommended)
The recommended way to install `terraform-provider-conjur` is to use the binary distributions from this project's
[GitHub Releases page](https://github.com/cyberark/terraform-provider-conjur/releases).
The packages are available for Linux, macOS and Windows.

Download and uncompress the latest release for your OS. This example uses the linux binary.

```sh-session
$ wget https://github.com/cyberark/terraform-provider-conjur/releases/download/$VERSION/terraform-provider-conjur-linux-amd64.tar.gz
$ tar -xvf terraform-provider-conjur*.tar.gz
```

Replace `$VERSION` above.

Now copy the binary to the Terraform's plugins folder. If this is your first plugin, you'll need to create the folder first.

```sh-session
$ mkdir -p ~/.terraform.d/plugins/
$ mv terraform-provider-conjur*/terraform-provider-conjur ~/.terraform.d/plugins/
```

### Homebrew (MacOS)

Add and update the CyberArk Tools Homebrew tap.

```sh-session
$ brew tap cyberark/tools
```

Install the provider and symlink it to Terraform's plugins directory.

```sh-session
$ brew install terraform-provider-conjur

$ mkdir -p ~/.terraform.d/plugins/
$ ln -sf /usr/local/Cellar/terraform-provider-conjur/$VERSION/bin/terraform-provider-conjur
```

Symlinking is necessary because
[Homebrew is sandboxed and cannot write to your home directory](https://github.com/Homebrew/brew/issues/2986).
Replace `$VERSION` above.
If Homebrew is installing somewhere other than `/usr/local/Cellar`, update the path as well.

### Compile from Source

If you wish to compile the provider from source code, you'll first need Go installed on your machine (version >=1.9 is required).

Clone repository to: `$GOPATH/src/github.com/cyberark/terraform-provider-conjur`

```sh-session
$ mkdir -p $GOPATH/src/github.com/cyberark

$ git clone https://github.com/cyberark/terraform-provider-conjur.git $GOPATH/src/github.com/cyberark/terraform-provider-conjur
```

Enter the provider directory and build the provider

```sh-session
$ cd $GOPATH/src/github.com/cyberark/terraform-provider-conjur
$ make build
```

Now copy the binary to the Terraform's plugins folder. If this is your first plugin, you'll need to create the folder first.

```sh-session
$ mkdir -p ~/.terraform.d/plugins/
$ mv terraform-provider-conjur ~/.terraform.d/plugins/
```

## Usage

### Provider configuration

#### Using environment variables

The provider uses [conjur-api-go](https://github.com/cyberark/conjur-api-go) to load its
configuration. `conjur-api-go` can be configured using environment variables:

```
export CONJUR_APPLIANCE_URL="https://localhost:8443"
export CONJUR_ACCOUNT="quick-start"
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

For example, if the environment is initialized as above, this configuration would
authenticate as `terraform-user` instead of `admin`:

```
# main.tf
provider "conjur" {
  login = "terraform-user"
  api_key = "x0dwqc3jrqkye3xhn7k62rw31c6216ewfe1wv71291jrqm4j15b3dg9"
}
```


### Fetch secrets

```
# main.tf
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
