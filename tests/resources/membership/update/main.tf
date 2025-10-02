variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}

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

resource "conjur_membership" "imported" {
  group_id    = "data/terraform/consumers"
  member_kind = "host"
  member_id   = "data/terraform/test/test-workload"
}

output "membership_id" {
  value = conjur_membership.imported.id
}

output "update_status" {
  value = conjur_membership.imported.member_id == "data/terraform/test/test-workload" ? "success" : "fail"
}
