variable "conjur_ssl_cert" {}
variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_authn_type" {}
variable "conjur_authn_service_id" {}
variable "conjur_secret_variable" {}
variable "authn_jwt_token" {}

# This wrapper resource forces the JWT value to become (known after apply) during the plan phase.
# We use this to simulate HCP behavior, where the workload identity token is unknown initially.
resource "terraform_data" "simulate_tfc_behavior" {
  input = var.authn_jwt_token
}

terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
      version = "~> 0"
    }
  }
}

provider "conjur" {
  appliance_url   = var.conjur_appliance_url
  account         = var.conjur_account
  authn_type      = var.conjur_authn_type
  service_id      = var.conjur_authn_service_id
  ssl_cert        = var.conjur_ssl_cert
  
  # Use the output from the wrapper resource instead of the variable directly.
  # This makes the attribute Unknown during the plan.
  authn_jwt_token = terraform_data.simulate_tfc_behavior.output
}

data "conjur_secret" "dbpass" {
  name = var.conjur_secret_variable
  
  # This forces the data source to re-read during apply 
  # because the input depends on the wrapper resource
  depends_on = [terraform_data.simulate_tfc_behavior]
}

output "dbpass-to-output" {
  value     = data.conjur_secret.dbpass.value
  sensitive = true
}

ephemeral "conjur_secret" "dbpass" {
  name = var.conjur_secret_variable
}

resource "local_file" "dbpass-to-file" {
  content = data.conjur_secret.dbpass.value != null ? data.conjur_secret.dbpass.value : "placeholder-for-plan"
  filename        = "${path.module}/../dbpass"
  file_permission = "0664"

  # Verify that the ephemeral secret matches the regular data source
  # Using a precondition to assert equality - this will fail if condition is false
  lifecycle {
    precondition {
      condition     = ephemeral.conjur_secret.dbpass.value == data.conjur_secret.dbpass.value
      error_message = "Ephemeral secret value does not match regular data source value"
    }
  }
}