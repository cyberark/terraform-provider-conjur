provider "conjur" {}

data "conjur_secret" "admin-password" {
   name = "postgres/admin-password"
}
