# terraform-provider-conjur

Terraform Conjur provider 

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
}
```

With environment variables:

```
export CONJUR_APPLIANCE_URL="http://localhost:8080"
export CONJUR_ACCOUNT="quick-start"
export CONJUR_AUTHN_LOGIN="admin"
export CONJUR_AUTHN_API_KEY="3ahcddy39rcxzh3ggac4cwk3j2r8pqwdg33059y835ys2rh2kzs2a"
```

**main.tf**

```
provider "conjur" {}
```

### Fetch secrets

**main.tf**

```
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

## Development

To run end to end tests: `./bin/test`.
