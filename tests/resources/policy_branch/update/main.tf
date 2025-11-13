variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}
variable "conjur_policy_branch_name" {}

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

resource "conjur_policy_branch" "imported" {
  branch = "data/terraform"
  name   = var.conjur_policy_branch_name

  annotations = {
    test    = "updated"
    env     = "terraform"
    updated = "true"
  }
}

output "policy_branch_full_id" {
  value = conjur_policy_branch.imported.full_id
}

output "update_status" {
  value = conjur_policy_branch.imported.annotations.test == "updated" ? "success" : "fail"
}
