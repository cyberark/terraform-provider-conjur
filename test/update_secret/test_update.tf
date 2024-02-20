terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
      version = "~> 0"
    }
  }
}

data "conjur_secret_update" "example" {
  name         = "terraform-example/dbpass"
  update_value = "NewSecretValue123"
}

data "conjur_secret" "dbpass" {
  name = "terraform-example/dbpass"
}

output "dbpass-to-output" {
  value = data.conjur_secret.dbpass.value
  sensitive = true
}

resource "local_file" "dbpass-to-file" {
  content = data.conjur_secret.dbpass.value
  filename = "${path.module}/../dbpass"
  file_permission = "0664"
}