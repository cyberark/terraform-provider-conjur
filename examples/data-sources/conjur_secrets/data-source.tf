data "conjur_secrets" "batch" {
  names = [
    "data/test/var-1",
    "data/test/var-2",
    "data/test/var-3"
  ]
  fail_on_error = false
}

ephemeral "conjur_secrets" "ephemeral_batch" {
  names = [
    "data/test/var-4",
    "data/test/var-5",
    "data/test/var-6"
  ]
  fail_on_error = true
}
