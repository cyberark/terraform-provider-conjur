data "conjur_secrets" "batch" {
  names = [
    "data/test/var-1",
    "data/test/var-2",
    "data/test/var-3"
  ]
}
