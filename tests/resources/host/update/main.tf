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

# Declared identically to create/main.tf (this directory's state is copied
# from create/, not imported) so neither authenticator is destroyed here -
# only the host's authn_descriptors below switches which one it points at.
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

# Descriptor update: remove the descriptor pointing at jwt_a and add one
# pointing at jwt_b. This is the only change from create/main.tf, so it
# exercises the PATCH /workloads/{path} update path (not a replace), and
# since both authenticators stay alive throughout, there's no risk of the
# host referencing an authenticator that's mid-destroy.
locals {
  authn_descriptors = [
    {
      type       = "api_key"
      service_id = null
      data       = null
    },
    {
      type       = "jwt"
      service_id = conjur_authenticator.jwt_b.name
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

output "update_status" {
  # jsonencode (rather than a raw ==) avoids Terraform inferring a
  # different composite type for local.authn_descriptors' object-literal
  # "data" values than the map(string) type the schema actually returns.
  value = jsonencode(conjur_host.test_app.authn_descriptors) == jsonencode(local.authn_descriptors) ? "success" : "fail"
}
