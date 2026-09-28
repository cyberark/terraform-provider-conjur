variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}
variable "conjur_group_name" {}

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

resource "conjur_group" "test_group" {
  name    = var.conjur_group_name
  branch = "data/terraform/test"
  annotations = {
    note = "UPDATED Group provisioned by Terraform",
    key3 = "value3"
  }
}

output "update_status" {
  value = conjur_group.test_group.annotations.note == "UPDATED Group provisioned by Terraform" && !contains(keys(conjur_group.test_group.annotations), "key2") && lookup(conjur_group.test_group.annotations, "key3", "") == "value3" ? "success" : "fail"
}
