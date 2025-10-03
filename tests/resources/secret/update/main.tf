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

resource "conjur_secret" "imported" {
  name    = var.conjur_secret_name
  branch = "/data/terraform/test"
  mime_type = "text/plain"
  value   = "myupdatedsecretvalue"
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
    note = "UPDATED TF managed secret",
    key2 = "value2"
  }
}

output "update_status" {
  value = conjur_secret.imported.annotations.note == "UPDATED TF managed secret" ? "success" : "fail"
}
