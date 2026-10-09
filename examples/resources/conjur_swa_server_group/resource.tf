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

# Server group using Gemini Enterprise attestation
resource "conjur_swa_server_group" "gemini_enterprise" {
  trust_domain_name = "prod.example.org"
  name              = "gemini-servers"
  description       = "Gemini Enterprise workload server group"

  attestation = {
    gemini_enterprise = {
      allowed_org_ids = ["123456789012", "210987654321"]
      audiences       = ["urn:panw:swa"]
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
      assume_role = "SWAServerRole"
      partition   = "aws"

      verify_organization = {
        management_account_id = "123456789012"
        assume_org_role       = "AWSOrganizationsReadOnlyAccess"
      }
    }
  }
}

# Server group using Kubernetes JWT (Projected Service Account Token via OIDC) attestation
resource "conjur_swa_server_group" "k8s_jwt" {
  trust_domain_name = "prod.example.org"
  name              = "k8s-jwt-servers"
  description       = "Kubernetes workload server group using JWT attestation"

  attestation = {
    k8s_jwt = {
      clusters = {
        "prod-cluster" = {
          issuer                      = "https://kubernetes.default.svc.cluster.local"
          audience                    = "swa-node-attestation"
          service_account_allow_list  = ["swa-system:swa-agent-payments", "swa-system:swa-agent-frontend"]
          # Use jwks_uri ...
          jwks_uri                    = "https://oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE/keys"
          # ...or public_keys for clusters with no reachable JWKS endpoint (e.g. OpenShift).
          # jwks_uri and public_keys are mutually exclusive.
          # public_keys = jsonencode({
          #   type  = "jwks"
          #   value = { keys = [...] }
          # })
        }
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
