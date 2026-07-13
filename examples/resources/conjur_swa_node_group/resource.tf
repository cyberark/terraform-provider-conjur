# Minimal node group (unix workload, no workload configuration)
resource "conjur_swa_node_group" "unix_nodes" {
  trust_domain_name = "prod.example.org"
  server_group_name = "prod-servers"
  name              = "prod-nodes"
  workload_type     = "unix"
  description       = "Production unix workload node group"
}

# Node group with a custom SPIFFE ID template and registration policies
resource "conjur_swa_node_group" "k8s_nodes" {
  trust_domain_name = "prod.example.org"
  server_group_name = "k8s-servers"
  name              = "k8s-nodes"
  workload_type     = "kubernetes"
  description       = "Kubernetes workload node group"

  workload_configuration = {
    spiffe_id_template = "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .k8s.ns }}/{{ .k8s.sa }}"
    workload_registration_policies = [
      "workload.k8s.ns == 'app'",
    ]
  }
}

