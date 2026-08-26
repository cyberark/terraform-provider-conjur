# Server group using X.509 Proof of Possession node attestation
resource "conjur_swa_server_group" "x509pop" {
  trust_domain_name = "prod.example.org"
  name              = "prod-servers"
  description       = "Production servers attested via X.509 POP"

  attestation = {
    x509pop = {
      ca_certificates = file("ca.pem")
    }
  }
}

# Server group using Kubernetes Projected Service Account Token (PSAT) attestation
resource "conjur_swa_server_group" "k8s" {
  trust_domain_name = "prod.example.org"
  name              = "k8s-servers"
  description       = "Kubernetes workload server group"

  attestation = {
    k8s_psat = {
      clusters = {
        "prod-cluster" = {
          service_account_allow_list = ["app:my-sa", "kube-system:metrics-sa"]
          audience                   = ["spiffe://prod.example.org"]
          allowed_pod_label_keys     = ["app", "version"]
          allowed_node_label_keys    = ["zone"]
        }
      }
    }
  }
}

# Server group using GCP Service Account attestation
resource "conjur_swa_server_group" "gcp" {
  trust_domain_name = "prod.example.org"
  name              = "gcp-servers"
  description       = "GCP workload server group"

  attestation = {
    gcp_service_account = {
      allowed_project_ids = ["project-a", "project-b"]
      audiences           = ["urn:panw:swa"]
    }
  }
}

# Server group using AWS Instance Identity Document (IID) attestation
resource "conjur_swa_server_group" "aws_iid" {
  trust_domain_name = "prod.example.org"
  name              = "aws-servers"
  description       = "AWS workload server group"

  attestation = {
    aws_iid = {
      assume_role = "arn:aws:iam::123456789012:role/SWAServerRole"
      partition   = "aws"

      verify_organization = {
        management_account_id = "123456789012"
        assume_org_role       = "AWSOrganizationsReadOnlyAccess"
      }
    }
  }
}

# Server group with no node attestation (attestation is optional)
resource "conjur_swa_server_group" "no_attestation" {
  trust_domain_name = "prod.example.org"
  name              = "unattested-servers"
  description       = "Server group without node attestation"
}
