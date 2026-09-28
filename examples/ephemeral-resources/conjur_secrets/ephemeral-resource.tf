ephemeral "conjur_secrets" "ephemeral_batch" {
  names = [
    "data/test/var-4",
    "data/test/var-5",
    "data/test/var-6"
  ]
  fail_on_error = true
}

# Ephemeral values can only be referenced from ephemeral contexts, such as write-only arguments.
resource "conjur_secret" "copy" {
  name             = "var-4-copy"
  branch           = "/data/test"
  value_wo         = ephemeral.conjur_secrets.ephemeral_batch.values["data/test/var-4"]
  value_wo_version = 1
}
