provider "conjur" {
  # appliance_url = "http://localhost:8080"
  # account = "quick-start"
  # login = "test"
  # api_key = "test"
  # ssl_cert = "-----BEGIN CERTIFICATE-----..."
  # ssl_cert_path = "/etc/conjur.pem"
}

data "conjur_secret" "secret1" {
  name = "my/shiny/dbpass"
}

output "secret1" {
  value = "${data.conjur_secret.secret1.value}"
  sensitive = false
}

resource "local_file" "secret1" {
  content = "${data.conjur_secret.secret1.value}"
  filename = "${path.module}/secret1"
}
