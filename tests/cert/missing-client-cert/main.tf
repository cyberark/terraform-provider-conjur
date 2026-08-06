# Negative test: authn-cert without client certificate.
# The provider must not successfully authenticate — Conjur requires mTLS and
# will reject the request when no client cert/key is supplied.
# Expected outcome: terraform apply exits with a non-zero status.
variable "conjur_ssl_cert" {}
variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_authn_service_id" {}
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
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = "cert"
  service_id    = var.conjur_authn_service_id
  host_id       = var.conjur_host_id
  ssl_cert      = var.conjur_ssl_cert
  # authn_cert and authn_cert_key intentionally omitted
}

data "conjur_secret" "dbpass" {
  name = var.conjur_secret_variable
}
