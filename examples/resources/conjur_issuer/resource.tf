resource "conjur_issuer" "my_aws_issuer" {
  id      = "my-aws-issuer"
  max_ttl = 3600

  aws = {
    access_key_id_secret_ref     = "data/terraform/aws-access-key-id"
    secret_access_key_secret_ref = "data/terraform/aws-secret-access-key"
  }
}
