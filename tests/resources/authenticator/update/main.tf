variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}
variable "conjur_authenticator_name" {}

terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
      version = "~> 0"
    }
  }
}

provider "conjur" {
  # Login and api_key are passed thorugh environmental variables
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = var.conjur_authn_type
  ssl_cert      = var.conjur_ssl_cert
}

# updates issuer
resource "conjur_authenticator" "imported" {
  type    = "jwt"
  name    = var.conjur_authenticator_name
  enabled = true
  data = {
    audience = "conjur-cloud",
    issuer   = "https://some-other-company.com",
    identity = {
      identity_path      = "my-apps/app-backend", 
      token_app_property = "sub",
      claim_aliases = {
        sub = "login",
        email = "email"
      },
      enforced_claims = ["sub","email"],
    },
    ca_cert = "-----BEGIN CERTIFICATE-----",
    public_keys = <<EOT
{
  "type": "jwks",
  "value": {
    "keys": [
      {
        "use": "sig",
        "kty": "RSA",
        "kid": "F8...",
        "alg": "RS256",
        "n": "8158...",
        "e": "AQAB"
      }
    ]
  }
}
EOT
  }
  annotations = {
    note = "Enable JWT login for CI runner in TF",
    key2 = "value2"
  }
}

output "update_status" {
  value = conjur_authenticator.imported.data.issuer == "https://some-other-company.com" ? "success" : "fail"
}
