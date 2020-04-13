provider "conjur" {
  # appliance_url = "http://localhost:8080"
  # account = "quick-start"
  # login = "test"
  # api_key = "test"
  # ssl_cert = "-----BEGIN CERTIFICATE-----..."
  # ssl_cert_path = "/etc/conjur.pem"
}

data "conjur_secret" "dbpass" {
  name = "terraform-example/dbpass"
}

output "dbpass-to-output" {
  value = data.conjur_secret.dbpass.value
  sensitive = false
}

resource "local_file" "dbpass-to-file" {
  content = data.conjur_secret.dbpass.value
  filename = "${path.module}/dbpass"
}
