# Server authenticated via a remote JWKS endpoint
resource "conjur_swa_server" "jwks" {
  name            = "my-swa-server"
  server_group_id = "prod.example.org/prod-servers"

  auth = {
    type     = "JWT"
    subject  = "system:serviceaccount:swa-ns:swa-server"
    issuer   = "https://issuer.example.org"
    jwks_uri = "https://issuer.example.org/.well-known/jwks.json"
    audience = "https://api.example.org"
  }
}

# Server authenticated via inline public keys (JWKS embedded in Terraform config)
resource "conjur_swa_server" "inline_keys" {
  name            = "inline-swa-server"
  server_group_id = "prod.example.org/prod-servers"

  auth = {
    type    = "JWT"
    subject = "system:serviceaccount:swa-ns:swa-server"
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
