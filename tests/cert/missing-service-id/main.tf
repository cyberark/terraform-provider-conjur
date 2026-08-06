# Negative test: authn-cert without service_id.
# The provider validates that service_id is required for authn_type = "cert"
# and must reject the configuration before even contacting Conjur.
# Expected outcome: terraform apply exits with a non-zero status.
variable "conjur_ssl_cert" {}
variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_authn_cert" {}
variable "conjur_authn_cert_key" {}
variable "conjur_host_id" {}
variable "conjur_secret_variable" {}

terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
      version = "~> 0"
    }
  }
}

provider "conjur" {
  appliance_url  = var.conjur_appliance_url
  account        = var.conjur_account
  authn_type     = "cert"
  # service_id intentionally omitted — provider must reject this configuration
  host_id        = var.conjur_host_id
  ssl_cert       = var.conjur_ssl_cert
  authn_cert     = var.conjur_authn_cert
  authn_cert_key = var.conjur_authn_cert_key
}

data "conjur_secret" "dbpass" {
  name = var.conjur_secret_variable
}
