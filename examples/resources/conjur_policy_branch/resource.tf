resource "conjur_policy_branch" "my_branch" {
  branch = "data/terraform"
  name   = var.conjur_policy_branch_name

  annotations = {
    test = "true"
    env  = "terraform"
  }
}