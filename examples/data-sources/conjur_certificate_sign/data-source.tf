data "conjur_certificate_sign" "my_cert" {
  # The name of the issuer registered in Conjur Cloud
  issuer_name = "my-cert-issuer"

  # CSR can be read from file or inline heredoc
  csr = trimspace(file("${path.module}/app.csr.pem"))

  # Optional parameters
  ttl  = "P3DT4H59M"
  zone = "My_Tenant\\Default"
}

# Example outputs
output "signed_certificate" {
  description = "PEM-encoded signed certificate"
  value       = data.conjur_certificate_sign.my_cert.certificate
  sensitive   = true
}

output "signing_chain" {
  description = "CA chain returned by the issuer"
  value       = data.conjur_certificate_sign.my_cert.chain
}
