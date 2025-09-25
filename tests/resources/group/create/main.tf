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
  # Login and api_key are passed thorugh environmental variables
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = var.conjur_authn_type
  ssl_cert      = var.conjur_ssl_cert
}

resource "conjur_group" "test_group" {
  name    = var.conjur_group_name
  branch = "data/terraform/test"
  annotations = {
    note = "Group provisioned by Terraform",
    key2 = "value2"
  }
}

# Save the IDs for later use in other stages
output "group_name" {
  value = conjur_group.test_group.name
}

output "create_status" {
  value = conjur_group.test_group.name != "" ? "success" : "fail"
}
