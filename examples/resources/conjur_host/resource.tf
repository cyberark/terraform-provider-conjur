resource "conjur_host" "my_host" {
  name = "my-host"
  branch = "data/terraform/test"
  annotations = {
    description = "Workload managed by Terraform",
    environment = "development"
  }
  restricted_to = ["1.2.4.5", "10.20.30.10"]
  authn_descriptors = [
    {
      type = "api_key"
    }
  ]
}
