data "conjur_secret" "my_secret" {
  name = "data/test/var-name"
  version = 2
}

# Ephemeral resource - secret value is NOT stored in Terraform state
# Useful when you need secret values during operations but don't want them persisted
ephemeral "conjur_secret" "my_ephemeral_secret" {
  name = "data/test/var-name"
  version = 2
}
