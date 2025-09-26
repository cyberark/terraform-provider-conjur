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
  # Login and api_key are passed through environmental variables
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = var.conjur_authn_type
  ssl_cert      = var.conjur_ssl_cert
}

resource "conjur_authenticator" "jwt_authenticator" {
  type    = "jwt"
  name    = var.conjur_authenticator_name
  enabled = true
  data = {
    audience = "conjur-cloud",
    issuer   = "https://mycompany.com",
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
    public_keys = "{\"type\":\"jwks\",\"value\":{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"F8...\",\"kty\":\"RSA\",\"n\":\"8158...\",\"use\":\"sig\"}]}}"
  }
  annotations = {
    note = "Enable JWT login for CI runner in TF",
    key2 = "value2"
  }
}

# Save the IDs for later use in other stages
output "authenticator_name" {
  value = conjur_authenticator.jwt_authenticator.name
}

output "create_status" {
  value = conjur_authenticator.jwt_authenticator.name != "" ? "success" : "fail"
}
