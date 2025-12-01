resource "conjur_policy_branch" "my_branch" {
  branch = "data/terraform"
  name   = "my-branch-name"

  annotations = {
    test = "true"
    env  = "terraform"
  }
}