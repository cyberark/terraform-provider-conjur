resource "conjur_group" "my_group" {
  name    = "my-group"
  branch = "data/terraform"
  annotations = {
    description = "Group managed by Terraform",
    environment = "development"
  }
}