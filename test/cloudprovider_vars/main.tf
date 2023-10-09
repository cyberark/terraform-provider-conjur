variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_authn_login" {}
variable "conjur_api_key" {}


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
  login         = var.conjur_authn_login
  api_key       = var.conjur_api_key
}

data "conjur_secret" "cloud_dbpass" {
  name = "data/vault/ADO_Secret/ado_secret_apikey/username"
}

output "dbpass-to-output" {
  value     = data.conjur_secret.cloud_dbpass.value
  sensitive = true
}

resource "local_file" "dbpass-to-file" {
  content         = data.conjur_secret.cloud_dbpass.value
  filename        = "${path.module}/../dbpass"
  file_permission = "0664"
}
