variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}
variable "conjur_host_name" {}

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

# The workload API rejects a "jwt" authn_descriptor unless its service_id
# names an existing, configured authn-jwt webservice, so both candidates the
# host's authn_descriptors will ever point at (jwt_a here, jwt_b once
# update/main.tf switches to it) are provisioned upfront. They stay declared
# identically in update/main.tf too, so descriptor updates never require
# destroying an authenticator a descriptor still (or again) points at.
resource "conjur_authenticator" "jwt_a" {
  type    = "jwt"
  name    = "${var.conjur_host_name}-jwt-a"
  enabled = true
  data = {
    audience = "conjur-cloud",
    issuer   = "https://mycompany.com",
    identity = {
      identity_path      = "data/terraform/test",
      token_app_property = "sub",
      claim_aliases = {
        sub   = "login",
        email = "email"
      },
      enforced_claims = ["sub", "email"],
    },
    ca_cert     = "-----BEGIN CERTIFICATE-----",
    public_keys = "{\"type\":\"jwks\",\"value\":{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"F8...\",\"kty\":\"RSA\",\"n\":\"8158...\",\"use\":\"sig\"}]}}"
  }
}

resource "conjur_authenticator" "jwt_b" {
  type    = "jwt"
  name    = "${var.conjur_host_name}-jwt-b"
  enabled = true
  data = {
    audience = "conjur-cloud",
    issuer   = "https://mycompany.com",
    identity = {
      identity_path      = "data/terraform/test",
      token_app_property = "sub",
      claim_aliases = {
        sub   = "login",
        email = "email"
      },
      enforced_claims = ["sub", "email"],
    },
    ca_cert     = "-----BEGIN CERTIFICATE-----",
    public_keys = "{\"type\":\"jwks\",\"value\":{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"F8...\",\"kty\":\"RSA\",\"n\":\"8158...\",\"use\":\"sig\"}]}}"
  }
}

locals {
  # Explicit null service_id/data on every element so the list has a single,
  # uniform element type - this must match exactly what conjur_host.test_app
  # reports back, so the create_status/update_status assertions below can
  # compare against it directly instead of just checking for containment.
  authn_descriptors = [
    {
      type       = "api_key"
      service_id = null
      data       = null
    },
    {
      type       = "jwt"
      service_id = conjur_authenticator.jwt_a.name
      data = {
        sub = "tf-workload-identity"
      }
    }
  ]
}

resource "conjur_host" "test_app" {
  name   = var.conjur_host_name
  branch = "data/terraform/test"
  annotations = {
    note = "Workload provisioned by Terraform",
    key2 = "value2"
  }
  restricted_to     = ["1.2.4.5", "10.20.30.10"]
  authn_descriptors = local.authn_descriptors
}

# Save the IDs for later use in other stages
output "host_name" {
  value = conjur_host.test_app.name
}

output "create_status" {
  # jsonencode (rather than a raw ==) avoids Terraform inferring a
  # different composite type for local.authn_descriptors' object-literal
  # "data" values than the map(string) type the schema actually returns.
  value = conjur_host.test_app.name != "" && jsonencode(conjur_host.test_app.authn_descriptors) == jsonencode(local.authn_descriptors) ? "success" : "fail"
}
