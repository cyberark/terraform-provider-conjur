variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}
variable "conjur_trust_domain_name" {}

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

resource "conjur_swa_trust_domain" "imported" {
  name = var.conjur_trust_domain_name

  jwt = {
    token_ttl = 600
  }

  x509 = {
    workload_ttl = 7200
  }
}

output "update_status" {
  value = conjur_swa_trust_domain.imported.jwt.token_ttl == 600 ? "success" : "fail"
}

