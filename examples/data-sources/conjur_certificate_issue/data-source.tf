data "conjur_certificate_issue" "my_cert" {
  # The name of the issuer registered in Secrets Manager
  issuer_name = "my-cert-issuer"

  common_name   = "db.internal.example.com"
  organization  = "Example Corp"
  org_units     = ["IT Security", "Infrastructure"]
  locality      = "Chicago"
  state         = "IL"
  country       = "US"

  # Optional Subject Alternative Names
  dns_names       = ["db.internal.example.com", "db"]
  ip_addresses    = ["10.0.1.12"]
  email_addresses = ["admin@example.com"]
  uris            = ["spiffe://example.com/service/db"]

  key_type        = "RSA_2048"
  ttl             = "P3DT4H59M"
  zone            = "My_Tenant\\Default"
}

# Example outputs
output "issued_certificate" {
  description = "PEM-encoded certificate"
  value       = data.conjur_certificate_issue.my_cert.certificate
  sensitive   = true
}

output "issued_private_key" {
  description = "Private key associated with the issued certificate"
  value       = data.conjur_certificate_issue.my_cert.private_key
  sensitive   = true
}

output "issued_chain" {
  description = "Certificate chain returned by the issuer"
  value       = data.conjur_certificate_issue.my_cert.chain
}
