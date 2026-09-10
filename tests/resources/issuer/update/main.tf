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

# Named "imported" because bin/run_resource_tests imports the issuer created in ../create into
# this directory's state before applying
resource "conjur_issuer" "imported" {
  id = var.conjur_issuer_name
  # Raised from the 900 set at create time; a decrease is rejected at plan time
  max_ttl = 43200

  # Rotated onto the second credential pair, declared alongside the first in
  # conf/policy/api-key/root.yml
  aws = {
    access_key_id_secret_ref     = "data/terraform/aws-access-key-id-2"
    secret_access_key_secret_ref = "data/terraform/aws-secret-access-key-2"
  }
}

output "update_status" {
  value = conjur_issuer.imported.max_ttl == 43200 && conjur_issuer.imported.aws.access_key_id_secret_ref == "data/terraform/aws-access-key-id-2" ? "success" : "fail"
}
