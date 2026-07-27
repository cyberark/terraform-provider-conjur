variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}
variable "conjur_trust_domain_name" {}
variable "conjur_server_group_name" {}

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

resource "conjur_swa_trust_domain" "td" {
  name = var.conjur_trust_domain_name

  jwt = {
    token_ttl = 300
  }
}

resource "conjur_swa_server_group" "test" {
  name              = var.conjur_server_group_name
  trust_domain_name = conjur_swa_trust_domain.td.name
  description       = "Server group managed by Terraform"

  attestation = {
    x509pop = {
      ca_certificates = var.conjur_ssl_cert
    }
  }
}

output "server_group_id" {
  value = conjur_swa_server_group.test.id
}

output "create_status" {
  value = conjur_swa_server_group.test.id != "" ? "success" : "fail"
}

