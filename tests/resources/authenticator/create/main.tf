variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}

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

resource "conjur_authenticator" "jwt_authenticator_all_fields" {
  type    = "jwt"
  name    = "my-tf-app-authenticator"
  enabled = true
  owner = {
    kind = "user",
    id = "admin"
  }
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

# Requires 'data' block even though docs say optional
resource "conjur_authenticator" "jwt_authenticator_required_only" {
  type    = "jwt"
  name    = "my-tf-app-authenticator-minimal"
  data = {
    jwks_uri = "https://mycompany.com/.well-known/jwks"
  }
}


# Save the IDs for later use in other stages
output "authenticator_name_all_fields" {
  value = conjur_authenticator.jwt_authenticator_all_fields.name
}

output "create_status_all_fields" {
  value = conjur_authenticator.jwt_authenticator_all_fields.name != "" ? "success" : "fail"
}

output "authenticator_name_required_only" {
  value = conjur_authenticator.jwt_authenticator_required_only.name
}

output "create_status_required_only" {
  value = conjur_authenticator.jwt_authenticator_required_only.name != "" ? "success" : "fail"
}
