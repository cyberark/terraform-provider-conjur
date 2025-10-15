resource "conjur_permission" "my_privileges" {
  role = {
    name     = "test-workload"
    kind   = "host"
    branch = "data/terraform/test"
  }
  resource = {
    name     = "workload-secret"
    kind   = "variable"
    branch = "data/terraform/test"
  }
  privileges = ["read", "execute"]
}
