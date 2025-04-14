variable "conjur_ssl_cert" {}
variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_authn_type" {}
variable "conjur_authn_service_id" {}
variable "conjur_secret_variable" {}
variable "authn_jwt_token" {}


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
  authn_type    = var.conjur_authn_type
  service_id    = var.conjur_authn_service_id
  ssl_cert      = var.conjur_ssl_cert
  authn_jwt_token = var.authn_jwt_token
}

data "conjur_secret" "dbpass" {
  name = var.conjur_secret_variable
}

output "dbpass-to-output" {
  value     = data.conjur_secret.dbpass.value
  sensitive = true
}

resource "local_file" "dbpass-to-file" {
  content         = data.conjur_secret.dbpass.value
  filename        = "${path.module}/../../dbpass"
  file_permission = "0664"
}
