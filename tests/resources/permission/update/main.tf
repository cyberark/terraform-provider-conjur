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
  # Login and api_key are passed through environmental variables
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = var.conjur_authn_type
  ssl_cert      = var.conjur_ssl_cert
}

// Try to remove a permission
resource "conjur_permission" "imported" {
  role = {
    name     = "test-workload"
    kind   = "host"
    branch = "data/terraform/test"
  }
  resource = {
    name     = "workload-secret"
    kind   = "variable"
    branch = "data/terraform/test"
  }
  privileges = ["read"]
}

output "update_status" {
  value = toset(conjur_permission.imported.privileges) == toset(["read"]) ? "success" : "fail"
}
