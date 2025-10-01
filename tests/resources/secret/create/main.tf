variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}
variable "conjur_secret_name" {}

terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
      version = "~> 0"
    }
  }
}

provider "conjur" {
  # Login and api_key are passed through environmental variables
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = var.conjur_authn_type
  ssl_cert      = var.conjur_ssl_cert
}

resource "conjur_secret" "test_secret" {
  name    = var.conjur_secret_name
  branch = "/data/terraform/test"
  mime_type = "text/plain"
  value   = "mysecretvalue"
  permissions = [
    {
      subject = {
        kind = "host"
        id = "data/terraform/test/test-workload"
      }
      privileges = ["read", "execute"]
    }
  ]
  annotations = {
    note = "TF managed secret",
    key2 = "value2"
  }
}

# Save the IDs for later use in other stages
output "secret_name" {
  value = conjur_secret.test_secret.name
}

output "create_status" {
  value = conjur_secret.test_secret.name != "" ? "success" : "fail"
}
