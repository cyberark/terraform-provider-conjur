variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}
variable "conjur_trust_domain_name" {}
variable "conjur_server_group_name" {}
variable "conjur_server_name" {}

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

resource "conjur_swa_server_group" "sg" {
  name              = var.conjur_server_group_name
  trust_domain_name = conjur_swa_trust_domain.td.name

  node_attestation = {
    x509pop = {
      ca_certificates = var.conjur_ssl_cert
    }
  }
}

resource "conjur_swa_server" "imported" {
  name            = "${var.conjur_server_name}-updated"
  server_group_id = conjur_swa_server_group.sg.id

  auth = {
    type     = "JWT"
    subject  = "system:serviceaccount:default:agent-updated"
    issuer   = "https://issuer.example.org"
    jwks_uri = "https://issuer.example.org/.well-known/jwks.json"
    audience = "conjur-cloud"
  }
}

output "update_status" {
  value = conjur_swa_server.imported.name == "${var.conjur_server_name}-updated" ? "success" : "fail"
}

