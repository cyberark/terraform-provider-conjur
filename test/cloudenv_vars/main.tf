terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
      version = "~> 0"
    }
  }
}

provider "conjur" {
  # All variables for this tests are passed in through env vars
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
