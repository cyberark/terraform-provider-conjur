variable "conjur_ssl_cert" {}
variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_authn_login" {}
variable "conjur_authn_type" {}
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
  authn_type    = var.conjur_authn_type
  login         = var.conjur_authn_login
  ssl_cert      = var.conjur_ssl_cert
}

data "conjur_secret" "dbpass" {
  name = var.conjur_secret_variable
}

output "dbpass-to-output" {
  value     = data.conjur_secret.dbpass.value
  sensitive = true
}

ephemeral "conjur_secret" "dbpass" {
  name = var.conjur_secret_variable
}

resource "local_file" "dbpass-to-file" {
  content         = data.conjur_secret.dbpass.value
  filename        = "${path.module}/../dbpass"
  file_permission = "0664"

  # Verify that the ephemeral secret matches the regular data source
  # Using a precondition to assert equality - this will fail if condition is false
  lifecycle {
    precondition {
      condition     = ephemeral.conjur_secret.dbpass.value == data.conjur_secret.dbpass.value
      error_message = "Ephemeral secret value does not match regular data source value"
    }
  }
}
