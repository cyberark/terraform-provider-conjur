terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
    }
  }
}

provider "conjur" {
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = var.conjur_authn_type
  login         = var.conjur_authn_login
  api_key       = var.conjur_api_key
  ssl_cert      = var.conjur_ssl_cert
}