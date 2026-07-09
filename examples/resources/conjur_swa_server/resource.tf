# Server authenticated via a remote JWKS endpoint
resource "conjur_swa_server" "jwks" {
  name            = "my-workload"
  server_group_id = "prod.example.org/prod-servers"

  auth = {
    type     = "JWT"
    subject  = "my-workload"
    issuer   = "https://issuer.example.org"
    jwks_uri = "https://issuer.example.org/.well-known/jwks.json"
    audience = "https://api.example.org"
  }
}

# Server authenticated via inline public keys (JWKS embedded in Terraform config)
resource "conjur_swa_server" "inline_keys" {
  name            = "inline-workload"
  server_group_id = "prod.example.org/prod-servers"

  auth = {
    type    = "JWT"
    subject = "inline-workload"
    issuer  = "https://issuer.example.org"
    public_keys = jsonencode({
      type  = "jwks"
      value = {
        keys = [
          {
            kty = "EC"
            crv = "P-256"
            x   = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
            y   = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            kid = "key-1"
          }
        ]
      }
    })
  }
}

# Server with identity claim mapping
resource "conjur_swa_server" "with_identity" {
  name            = "mapped-workload"
  server_group_id = "prod.example.org/prod-servers"

  auth = {
    type     = "JWT"
    subject  = "mapped-workload"
    issuer   = "https://issuer.example.org"
    jwks_uri = "https://issuer.example.org/.well-known/jwks.json"

    identity = {
      token_app_property = "sub"
      identity_path      = "/data/terraform/workloads"
      enforced_claims    = ["sub", "iss"]
      claim_aliases = {
        "user" = "sub"
      }
    }
  }
}

