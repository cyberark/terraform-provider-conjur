resource "conjur_secret" "my_secret" {
  name    = "my-secret"
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
    description = "Secret managed by Terraform",
    environment = "development"
  }
}