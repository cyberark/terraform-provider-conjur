variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}

# Randomized per run by generate_random_values() in bin/run_resource_tests
variable "conjur_issuer_name" {}

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

resource "conjur_issuer" "test_issuer" {
  id = var.conjur_issuer_name
  # Lowest value the API accepts; the update stage raises it to the highest (43200)
  max_ttl = 900

  # The referenced secrets are declared in conf/policy/api-key/root.yml and given their values
  # by bin/test. They are not created here with conjur_secret because that resource is SaaS-only,
  # while issuers also work on Self-Hosted.
  aws = {
    access_key_id_secret_ref     = "data/terraform/aws-access-key-id"
    secret_access_key_secret_ref = "data/terraform/aws-secret-access-key"
  }
}

# Save the IDs for later use in other stages
output "issuer_id" {
  value = conjur_issuer.test_issuer.id
}

output "create_status" {
  value = conjur_issuer.test_issuer.max_ttl == 900 ? "success" : "fail"
}
