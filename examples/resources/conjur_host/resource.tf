resource "conjur_host" "my_host" {
  name   = "my-host"
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

resource "conjur_host" "my_jwt_host" {
  name   = "my-jwt-host"
  branch = "data/terraform/test"
  authn_descriptors = [
    {
      type       = "jwt"
      service_id = "my-jwt-service"
      # "data" maps authenticator-specific keys (here, JWT claim names) to
      # expected values. Express multiple expected values
      # for a single key as a JSON array string, e.g. an "aud" claim that
      # must match more than one audience.
      data = {
        sub = "my-workload-identity"
        aud = jsonencode(["app1", "app2"])
      }
    }
  ]
}

