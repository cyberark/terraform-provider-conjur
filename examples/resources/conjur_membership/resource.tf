resource "conjur_membership" "my_group_membership" {
  group_id    = "data/terraform/my-group"
  member_kind = "host"
  member_id   = "data/terraform/test/my-workload"
}
