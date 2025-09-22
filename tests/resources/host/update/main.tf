variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}
variable "conjur_host_name" {}

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

resource "conjur_host" "test_app" {
  name = var.conjur_host_name
  branch = "data/terraform/test"
  annotations = {
    note = "UPDATED workload provisioned by Terraform",
    key2 = "value2"
  }
  restricted_to = ["1.2.4.5", "10.20.30.10"]
  authn_descriptors = [
    {
      type = "api_key"
    }
  ]
}

output "update_status" {
  value = conjur_host.test_app.annotations.note == "UPDATED workload provisioned by Terraform" ? "success" : "fail"
}

