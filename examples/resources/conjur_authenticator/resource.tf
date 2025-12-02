resource "conjur_authenticator" "jwt_authenticator" {
  type    = "jwt"
  name    = "my-service-id"
  enabled = true
  data = {
    audience = "conjur-cloud",
    issuer   = "https://mycompany.com",
    identity = {
      identity_path      = "my-apps/app-backend", 
      token_app_property = "sub",
      claim_aliases = {
        sub = "login",
        email = "email"
      },
      enforced_claims = ["sub","email"],
    },
    ca_cert = "-----BEGIN CERTIFICATE-----",
    public_keys = "{\"type\":\"jwks\",\"value\":{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"F8...\",\"kty\":\"RSA\",\"n\":\"8158...\",\"use\":\"sig\"}]}}"
  }
  annotations = {
    note = "Enable JWT login for CI runner in TF",
    key2 = "value2"
  }
}
