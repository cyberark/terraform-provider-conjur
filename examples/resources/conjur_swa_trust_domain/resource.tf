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

# Trust domain with custom certificate and built-in CA configuration.
# Attributes you omit take the server defaults and are reported in state.
resource "conjur_swa_trust_domain" "custom_ca" {
  name = "ca.example.org"

  x509 = {
    workload_ttl                 = 3600
    intermediate_certificate_ttl = 172800 # at least twice workload_ttl
    intermediate_key_algorithm   = "EC_P384"

    ca = {
      type = "builtin"
      config = {
        # Changes to root_ca_ttl and root_key_algorithm apply to the next
        # root CA generation only.
        root_ca_ttl                    = 20736000
        root_key_algorithm             = "EC_P384"
        root_rotation_trigger_fraction = 0.75
      }
    }
  }
}
