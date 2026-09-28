variable "aws_access_key_id" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "aws_secret_access_key" {
  type      = string
  sensitive = true
  ephemeral = true
}

# The AWS credentials are written with the write-only value_wo attribute so they are never stored in
# the Terraform state or plan. Bump value_wo_version to push a rotated value.
resource "conjur_secret" "aws_access_key_id" {
  name             = "aws-access-key-id"
  branch           = "/data/terraform"
  value_wo         = var.aws_access_key_id
  value_wo_version = 1
}

resource "conjur_secret" "aws_secret_access_key" {
  name             = "aws-secret-access-key"
  branch           = "/data/terraform"
  value_wo         = var.aws_secret_access_key
  value_wo_version = 1
}

resource "conjur_issuer" "my_aws_issuer" {
  id      = "my-aws-issuer"
  max_ttl = 3600

  aws = {
    access_key_id_secret_ref     = "${trimprefix(conjur_secret.aws_access_key_id.branch, "/")}/${conjur_secret.aws_access_key_id.name}"
    secret_access_key_secret_ref = "${trimprefix(conjur_secret.aws_secret_access_key.branch, "/")}/${conjur_secret.aws_secret_access_key.name}"
  }
}
