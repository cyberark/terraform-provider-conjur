variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_secret_variable" {}
variable "conjur_authn_type" {}
variable "conjur_ssl_cert" {}
variable "conjur_secret_name" {}

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

resource "conjur_secret" "test_secret" {
  name    = var.conjur_secret_name
  branch = "/data/terraform/test"
  mime_type = "text/plain"
  value   = "mysecretvalue"
  permissions = [
    {
      subject = {
        kind = "host"
        id = "data/terraform/test/test-workload"
      }
      privileges = ["read", "execute"]
    },
    {
      subject = {
        kind = "host"
        id = "data/terraform/test/another-test-workload"
      }
      privileges = ["read"]
    }
  ]
  annotations = {
    note = "TF managed secret",
    key2 = "value2"
  }
}

# Save the IDs for later use in other stages
output "secret_name" {
  value = conjur_secret.test_secret.name
}

output "create_status" {
  value = conjur_secret.test_secret.name != "" ? "success" : "fail"
}

# Test write-only attribute: Create with value_wo and version
# Note: value_wo is write-only and cannot be output or referenced in state.
resource "conjur_secret" "test_wo" {
  name            = "${var.conjur_secret_name}-wo"
  branch          = "/data/terraform/test"
  value_wo        = "initial-secret-value-wo"
  value_wo_version = 1
  annotations = {
    test_type = "write-only"
  }
}

# Third secret used to exercise batch secret retrieval alongside test_secret and test_wo.
resource "conjur_secret" "test_secret2" {
  name      = "${var.conjur_secret_name}-2"
  branch    = "/data/terraform/test"
  mime_type = "text/plain"
  value     = "mysecretvalue2"
}

# Batch secret retrieval (strict): reads the three secrets created above via the batch
# data source and ephemeral resource. Referencing the secret names plus depends_on defers
# the reads to apply, after the secrets exist.
data "conjur_secrets" "batch" {
  names = [
    "data/terraform/test/${conjur_secret.test_secret.name}",
    "data/terraform/test/${conjur_secret.test_wo.name}",
    "data/terraform/test/${conjur_secret.test_secret2.name}",
  ]
  fail_on_error = true
  depends_on    = [conjur_secret.test_secret, conjur_secret.test_wo, conjur_secret.test_secret2]
}

# Ephemeral resources are opened during the plan phase whenever their configuration is fully
# known; unlike data sources, depends_on does NOT defer the open. Deriving names from the
# (apply-time) data source result keeps this config unknown at plan, so Terraform defers Open()
# to apply after the secrets exist. keys(...) returns exactly the names the batch data source
# successfully retrieved.
ephemeral "conjur_secrets" "batch" {
  names         = keys(data.conjur_secrets.batch.values)
  fail_on_error = true
}

# Batch secret retrieval (non-strict): includes an unknown name to exercise the warning path.
# apply must still succeed and the unknown key must be absent from values.
data "conjur_secrets" "batch_warn" {
  names = [
    "data/terraform/test/${conjur_secret.test_secret.name}",
    "data/terraform/test/does-not-exist-${var.conjur_secret_name}",
  ]
  fail_on_error = false
  depends_on    = [conjur_secret.test_secret]
}

# Validation for batch retrieval. Content is static so no secret is written to disk; the
# preconditions perform all assertions and fail terraform apply if any batch read is wrong.
resource "local_file" "batch_check" {
  content  = "batch-ok"
  filename = "${path.module}/../batch_check"

  lifecycle {
    precondition {
      condition     = data.conjur_secrets.batch.values["data/terraform/test/${conjur_secret.test_secret.name}"] == conjur_secret.test_secret.value
      error_message = "Batch data source value for test_secret does not match"
    }
    precondition {
      condition     = data.conjur_secrets.batch.values["data/terraform/test/${conjur_secret.test_wo.name}"] == "initial-secret-value-wo"
      error_message = "Batch data source value for write-only secret does not match"
    }
    precondition {
      condition     = data.conjur_secrets.batch.values["data/terraform/test/${conjur_secret.test_secret2.name}"] == conjur_secret.test_secret2.value
      error_message = "Batch data source value for test_secret2 does not match"
    }
    precondition {
      condition     = ephemeral.conjur_secrets.batch.values["data/terraform/test/${conjur_secret.test_secret.name}"] == data.conjur_secrets.batch.values["data/terraform/test/${conjur_secret.test_secret.name}"]
      error_message = "Ephemeral batch value does not match data source batch value"
    }
    precondition {
      condition     = length(data.conjur_secrets.batch_warn.values) == 1
      error_message = "Warning-path batch should return only the existing secret (unknown name must be excluded)"
    }
  }
}
