# Minimal trust domain — uses server-side defaults for JWT and X.509
resource "conjur_swa_trust_domain" "default" {
  name = "prod.example.org"
}

# Trust domain with custom JWT SVID configuration
resource "conjur_swa_trust_domain" "with_jwt" {
  name = "dev.example.org"

  jwt = {
    signature_algorithm = "ES256"
    signing_key_type    = "EC_P256"
    signing_key_ttl     = 3600
    token_ttl           = 600
  }
}

# Trust domain with both JWT and X.509 SVID configuration
resource "conjur_swa_trust_domain" "full" {
  name = "staging.example.org"

  jwt = {
    signature_algorithm = "RS512"
    signing_key_type    = "RSA_4096"
    signing_key_ttl     = 86400
    token_ttl           = 300
  }

  x509 = {
    workload_ttl = 3600
  }
}

