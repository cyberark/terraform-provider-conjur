# terraform-provider-conjur 

Terraform provider for [Conjur](https://www.conjur.org).

[![GitHub release](https://img.shields.io/github/release/cyberark/terraform-provider-conjur.svg)](https://github.com/cyberark/terraform-provider-conjur/releases/latest)

[![Maintainability](https://api.codeclimate.com/v1/badges/e9fc0a2de573aa189a3c/maintainability)](https://codeclimate.com/github/cyberark/terraform-provider-conjur/maintainability)

---

## Installation

### Using terraform-provider-conjur with Conjur Open Source 

Are you using this project with [Conjur Open Source](https://github.com/cyberark/conjur)? Then we 
**strongly** recommend choosing the version of this project to use from the latest [Conjur OSS 
suite release](https://docs.conjur.org/Latest/en/Content/Overview/Conjur-OSS-Suite-Overview.html). 
Conjur maintainers perform additional testing on the suite release versions to ensure 
compatibility. When possible, upgrade your Conjur version to match the 
[latest suite release](https://docs.conjur.org/Latest/en/Content/ReleaseNotes/ConjurOSS-suite-RN.htm); 
when using integrations, choose the latest suite release that matches your Conjur version. For any 
questions, please contact us on [Discourse](https://discuss.cyberarkcommons.org/c/conjur/5).

### Binaries (Recommended)
The recommended way to install `terraform-provider-conjur` is to use the binary distributions from this project's
[GitHub Releases page](https://github.com/cyberark/terraform-provider-conjur/releases).
The packages are available for Linux, macOS and Windows.

Download and uncompress the latest release for your OS. This example uses the linux binary.

_Note: Replace `$VERSION` with the one you want to use. See [releases](https://github.com/cyberark/terraform-provider-conjur/releases)
page for available versions._

```sh
$ wget https://github.com/cyberark/terraform-provider-conjur/releases/download/v$VERSION/terraform-provider-conjur-$VERSION-linux-amd64.tar.gz
$ tar -xvf terraform-provider-conjur*.tar.gz
```


If you already have an unversioned plugin that was previously downloaded, we first need
to remove it:
```sh
$ rm -f ~/.terraform.d/plugins/terraform-provider-conjur
```

Now copy the new binary to the Terraform's plugins folder. If this is your first plugin,
you will need to create the folder first.

```sh
$ mkdir -p ~/.terraform.d/plugins/
$ mv terraform-provider-conjur*/terraform-provider-conjur* ~/.terraform.d/plugins/
```

### Homebrew (MacOS)

Add and update the [CyberArk Tools Homebrew tap](https://github.com/cyberark/homebrew-tools).

```sh
$ brew tap cyberark/tools
```

Install the provider and symlink it to Terraform's plugins directory. Symlinking is
necessary because [Homebrew is sandboxed and cannot write to your home directory](https://github.com/Homebrew/brew/issues/2986).

_Note: Replace `$VERSION` with the appropriate plugin version_

```sh
$ brew install terraform-provider-conjur

$ mkdir -p ~/.terraform.d/plugins/

$ # If Homebrew is installing somewhere other than `/usr/local/Cellar`, update the path as well.
$ ln -sf /usr/local/Cellar/terraform-provider-conjur/$VERSION/bin/terraform-provider-conjur_* \
    ~/.terraform.d/plugins/
```

### Compile from Source

If you wish to compile the provider from source code, you will first need Go installed
on your machine (version >=1.12 is required).

- Clone repository and go into the cloned directory
```sh
$ git clone https://github.com/cyberark/terraform-provider-conjur.git
$ cd terraform-provider-conjur
```
- Build the provider

```sh
$ mkdir -p ~/.terraform.d/plugins/
$ # Note: If a static binary is required, use ./bin/build to create the executable
$ go build -o ~/.terraform.d/plugins/terraform-provider-conjur main.go
```

## Usage

### Workflow

Terraform can be run manually by users, but it is often run by machines.
Conjur supports authentication and authorization for both.

If you are logged into the [Conjur CLI](https://docs.conjur.org/Latest/en/Content/Tools/cli.html),
this provider will read your configuration.
If you have applied [Conjur machine identity](https://www.conjur.org/tutorials/policy/applications.html),
this provider will read the machine's configuration.

To access the values of secrets, the user/machine needs `execute` privilege
on the Conjur variables referenced in your Terraform manifests.

For more details, see the "Authentication" section
[on this page](https://docs.conjur.org/Latest/en/Content/Integrations/terraform.htm).

### Provider configuration using API Key

The provider uses [conjur-api-go](https://github.com/cyberark/conjur-api-go) to load its
configuration. `conjur-api-go` can be configured using environment variables or using the
provider configuration in the `.tf` file.

#### Using environment variables

```sh
export CONJUR_APPLIANCE_URL="https://conjur-server"
export CONJUR_ACCOUNT="myorg"
export CONJUR_AUTHN_LOGIN="admin"
export CONJUR_AUTHN_API_KEY="3ahcddy39rcxzh3ggac4cwk3j2r8pqwdg33059y835ys2rh2kzs2a"
export CONJUR_CERT_FILE="/etc/conjur.pem"
```

No other configuration is necessary in `main.tf`:

```terraform
# main.tf

# Configure the Conjur provider using the required_providers stanza
# required with Terraform 0.13 and beyond. You may optionally use version
# directive to prevent breaking changes occurring unannounced.
terraform {
  required_providers {
    conjur = {
      source  = "cyberark/conjur"
    }
  }
}

provider "conjur" {}
```

#### Using attributes

In addition, the provider can be configured using attributes in the
configuration. Attributes specified in `main.tf` override the configuration loaded by
`conjur-api-go`.

For example, with `conjur_api_key` and `conjur_ssl_cert`defined as
[input variables](https://www.terraform.io/docs/configuration/variables.html), this
type of configuration could be used:

```terraform
# main.tf
variable "conjur_api_key" {}
variable "conjur_ssl_cert" {}
# If you have the certificate as a file, use this line instead
# variable "conjur_ssl_cert_path" {}

provider "conjur" {
  appliance_url = "http://conjur-server"
  ssl_cert = var.conjur_ssl_cert
  # If you have the certificate as a file, use this line instead
  # ssl_cert_path = var.conjur_ssl_cert_path

  account = "myorg"

  login = "admin"
  api_key = var.conjur_api_key
}
```

**Notes on precedence of configuration variable setting:**

- If both the environment variable **and** `.tf` configuration are present for a
  configuration setting, the `.tf` configuration takes precedence and the environment
  variable will be ignored.
- If the `.tf` configuration does not include **both** `login` and `api_key`, then
  environment variables will be used for these values instead.

### Provider Configuration using Cloud Authenticators
**Below section describes the provider configuration with cloud authenticators**
### AWS IAM Role Authentication

#### Sample Policy of IAM for OSS/Enterprise

Create a IAM authenticator policy and save it as authn-iam.yml
```
- !policy
  id: conjur/authn-iam/prod
  body:
  - !webservice

  - !group clients

  - !permit
    role: !group clients
    privilege: [ read, authenticate ]
    resource: !webservice 
```
Load the policy to root
```
conjur policy load root authn-iam.yml
```

Create a policy for hosts and save it as authn-iam-host.yal

```
- !policy
  id: myspace
  body:
  - &variables
    - !variable database/username
    - !variable database/password
  # Create a group that will have permission to retrieve variables
  - !group secrets-users
  # Give the `secrets-users` group permission to retrieve variables
  - !permit
    role: !group secrets-users
    privilege: [ read, execute ]
    resource: *variables
  # Create a layer to hold this application's hosts
  - !layer
  # The host ID needs to match the AWS ARN of the role we wish to authenticate
  - !host 601277729239/InstanceReadJenkinsExecutorHostFactoryToken
  # Add our host into our layer
  - !grant
    role: !layer
    member: !host 601277729239/InstanceReadJenkinsExecutorHostFactoryToken
  # Give the host in our layer permission to retrieve variables
  - !grant
    member: !layer
    role: !group secrets-users

  # Give the host permission to authenticate using the IAM Authenticator
- !grant
  role: !group conjur/authn-iam/prod/clients
  member: !host myspace/601277729239/InstanceReadJenkinsExecutorHostFactoryToken
```

Load the policy into root
```
conjur policy load root authn-iam-host.yml
```
#### Sample Policy of IAM for Conjur Cloud

Create a policy file that defines the IAM authenticator and a workload (host) group whose members can use this IAM authenticator to authenticate to Conjur Cloud
```
- !policy
  id: prod
  body:
  - !webservice

  # Group for workloads that can authenticate using the authenticator
  - !group apps

  # Permissions for workloads group   
  - !permit
    role: !group apps
    privilege: [ read, authenticate ]
    resource: !webservice

  # Webservice for checking the status of the authenticator
  - !webservice status

  # Group for managing the authenticator and checking its status
  - !group operators

  # Permissions for the operators group to check the authenticator's status
  - !permit
    role: !group operators
    privilege: [ read ]
    resource: !webservice status

  # Permissions for the operators group to view and manage the authenticator
  - !permit
    role: !group operators
    privilege: [ read, update ]
    resource: !webservice
```
Enable the predefined IAM authenticator
```
conjur authenticator enable --id authn-iam/default
```
Save the policy using the following naming convention: authn-iam-<name>.yml; for example, authn-iam-prod.yml and Load the policy to conjur/authn-iam
```
conjur policy load -f authn-iam-prod.yml -b conjur/authn-iam
```
Define the AWS resource as a Conjur Cloud workload ID (host)
```
- !policy
  id: iam-ec2
  body:
    # Create a group to hold the hosts
    - !group workloads

    # Add hosts. The ID of each host needs to match the AWS ARN (i.e. AccountID/AWS role) of the AWS resource that it represents
    - !hostid: 601277729239/InstanceReadJenkinsExecutorHostFactoryToken #AccountID/AWSrole

        # Add the host into the group
    - !grant
      role: !group workloads
      member: !host 601277729239/InstanceReadJenkinsExecutorHostFactoryToken  #host id
```
Save the policy as authn-<service-id>-host.yaml. For example, authn-iam-ec2-host.yaml and Load the policy to any policy level under your policy branch, for example data
```
conjur policy load -f authn-iam-ec2-host.yaml -b data
```
Create a policy that adds the host, or group of hosts, as a member of the group defined in the IAM authenticator policy.
```
# Give all the hosts in the host group permission to authenticate using the IAM Authenticator
 
- !grant
  role: !group apps
  member: !group /data/iam-ec2/workloads
```
Save the policy as a YAML and load it to your IAM authenticator's branch
```
conjur policy load -f ec2-app-grants.yaml -b conjur/authn-iam/prod
```
Create a policy that adds the workload (host) (or the group that it's a member of) to the consumers group of the Safe
Example of adding the workload (host)
```
- !grant
  role: !group delegation/consumers
  member: !host /data/iam-ec2/01277729239/InstanceReadJenkinsExecutorHostFactoryToken
```
Example of adding the group that the workload is a member of
```
- !grant
  role: !group delegation/consumers
  member: !group /data/iam-ec2/workloads
```
Save the policy as a YAML, for example secrets-access.yaml, and load the policy file into the same branch as the Safe that contains your secrets
```
conjur policy load -f secrets-access.yaml -b data/vault/<your Safe>
```
#### Sample Terraform main.tf for IAM
```
variable "conjur_ssl_cert" {}
variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_host_id" {}
variable "conjur_authn_type" {}
variable "conjur_authn_service_id" {}

terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
      version = "~> 0"
    }
  }
}

provider "conjur" {
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = var.conjur_authn_type
  service_id    = var.conjur_authn_service_id
  host_id       = var.conjur_host_id
  ssl_cert      = var.conjur_ssl_cert
}
```
### Azure Authentication

#### Sample Access token from Azure

```
{
  "aud": "https://management.azure.com/",
  "iss": "https://sts.windows.net/af45c5e4-9498-4574-a8d8-5386b8d80162/",
  "iat": 1744698661,
  "nbf": 1744698661,
  "exp": 1744785361,
  "aio": "k2RgYNgza4Jl946WC3913wjUqS8vAgA=",
  "appid": "845610c6-b823-4476-9ad9-a51f6732d249",
  "appidacr": "2",
  "idp": "https://sts.windows.net/af45c5e4-9498-4574-a8d8-5386b8d80162/",
  "idtyp": "app",
  "oid": "d5448508-a2c6-467e-bf68-56a97bf102ea",
  "rh": "1.AWMB5MVFr5iUdEWo2FOGuNgBYkZIf3kAutdPukPawfj2MBPIAQBjAQ.",
  "sub": "d5448508-a2c6-467e-bf68-56a97bf102ea",
  "tid": "af45c5e4-9498-4574-a8d8-5386b8d80162",
  "uti": "Kbh_VEWVVEC6-jIidinCAA",
  "ver": "1.0",
  "xms_idrel": "7 16",
  "xms_mirid": "/subscriptions/fd4afc78-3701-4ffe-abcb-969239ef029e/resourcegroups/ResourceJWT/providers/Microsoft.Compute/virtualMachines/TerrUbuntu",
  "xms_tcdt": "1742960328"
}
```

#### Sample Policy of Azure Authentication for OSS/Enterprise

Create a policy as save it as authn-azure-AzureWS.yml

```
- !policy
  id: conjur/authn-azure/AzureTerraform
  body:
  - !webservice

  - !variable
    id: provider-uri

  - !group
    id: apps
    annotations:
      description: Group of hosts that can authenticate using the authn-azure/AzureTerraform authenticator

  - !permit
    role: !group apps
    privilege: [ read, authenticate ]
    resource: !webservice

  - !webservice
    id: status
    annotations:
      description: Status service to check that the authenticator is configured correctly

  - !group
    id: operators
    annotations:
      description: Group of users who can check the status of the authenticator

  - !permit
     role: !group operators
     privilege: [ read ]
     resource: !webservice status
```

Load the policy to root. Set the variable.
```
conjur policy load -f authn-azure-AzureWS.yml -b root
conjur variable set -i conjur/authn-azure/AzureTerraform/provider-uri -v https://sts.windows.net/af45c5e4-9498-4574-a8d8-5386b8d80162/
```

Create a policy for hosts and save it as authn-azure-hosts.yml
```
- !policy
  id: azure-apps
  body:
    # Create a group to hold this application's hosts
    - !group

    - &hosts
      - !host
        id: azureVM
        annotations:
          authn-azure/subscription-id: fd4afc78-3701-4ffe-abcb-969239ef029e
          authn-azure/resource-group: ResourceJWT
          # authn-azure/user-assigned-identity: {{ USER_ASSIGNED_IDENTITY }}
          # authn-azure/system-assigned-identity: {{ SYSTEM_ASSIGNED_IDENTITY }}

    # Add the host into the group
    - !grant
      role: !group
      members: *hosts
- !grant
  role: !group conjur/authn-azure/AzureTerraform/apps
  member: !group azure-apps
```
Load the policy file into any policy level
```
conjur policy load -f authn-azure-host.yaml -b root
```
Create a policy for secrets and save it as authn-azure-secrets.yml
```
- !policy
  id: secrets
  body:
    - !group consumers

    - !variable test-variable

    - !permit
      role: !group consumers
      privilege: [ read, execute ]
      resource: !variable test-variable

- !grant
  role: !group secrets/consumers
  member: !group azure-apps
```

Load the policy to root
```
conjur policy load -f authn-azure-secrets.yml -b root
```

#### Sample Policy of Azure Authentication for Conjur Cloud
Define Azure Authentication Policy
```
- !policy
  id: AzureWS
  body:
  - !webservice

  - !variable
    id: provider-uri

  - !group
    id: apps
    annotations:
      description: Group of hosts that can authenticate using the authn-azure/AzureWS authenticator

  - !permit
    role: !group apps
    privilege: [ read, authenticate ]
    resource: !webservice

  - !webservice
    id: status
    annotations:
      description: Status service to check that the authenticator is configured correctly

  - !group
    id: operators
    annotations:
      description: Group of users who can check the status of the authenticator

  - !permit
     role: !group operators
     privilege: [ read ]
     resource: !webservice status
```
Save the policy as a YAML file using the following file naming convention, authn-azure-<service-id>.yml, for example, authn-azure-AzureWS.yml, and load it into conjur/authn-azure
```
conjur policy load -f authn-azure-AzureWS.yml -b conjur/authn-azure
```
Populate the provider_uri variable with the provider_uri from Azure
```
conjur variable set -i conjur/authn-azure/AzureWS/provider-uri -v https://sts.windows.net/af45c5e4-9498-4574-a8d8-5386b8d80162/
```
Enable the Azure authenticator
```
conjur authenticator enable --id authn-azure/AzureWS
```
Define the Azure resource as a host
```
- !policy
  id: azure-apps
  body:
    # Create a group to hold this application's hosts
    - !group

    - &hosts
      - !host
        id: azureVM
        annotations:
          authn-azure/subscription-id: fd4afc78-3701-4ffe-abcb-969239ef029e
          authn-azure/resource-group: ResourceJWT
          # authn-azure/user-assigned-identity: {{ USER_ASSIGNED_IDENTITY }}
          # authn-azure/system-assigned-identity: {{ SYSTEM_ASSIGNED_IDENTITY }}

    # Add the host into the group
    - !grant
      role: !group
      members: *hosts
```
Save the policy as a YAML file, using the following naming convention:authn-azure-<service-id>-hosts.yaml, for example, authn-azure-AzureWS1-hosts.yaml and Load the policy file into any policy level under your policy branch, for example data/myspace
```
conjur policy load -f authn-azure-host.yaml -b data/myspace
```
Create a policy that adds the host, or group of hosts, as a member of the group defined in the Azure Authenticator policy
```
- !grant
  role: !group apps
  member: !group /data/myspace/azure-apps
```
Save the policy as app-grants.yaml, and load the policy file into conjur/authn-azure/<service-id>, for example
```
conjur policy load -f app-grants.yaml -b conjur/authn-azure/AzureWS
```
Define Conjur Cloud variables (secrets) and a group that has permissions on the variables
```
- !policy
  id: variablespace
  body:
  - &variables
    - !variable demo-variable
 
  # Create a group that has permission to retrieve secrets
  - !group secrets-users
 
  # Give the group permission to retrieve secrets
  - !permit
    role: !group secrets-users
    privilege: [ read, execute ]
    resource: *variables
   
# Give the hosts in the group permission to retrieve secrets
- !grant
  role: !group variablespace/secrets-users
  member: !group azure-apps
```
Save the policy as authn-azure-secrets.yaml, and load the policy file into the same branch as the host policy
```
conjur policy load -f authn-azure-secrets.yaml -b data/myspace
```
Populate the variable with a secret. Use the full path to the variable
```
conjur variable set -i data/myspace/variablespace/demo-variable -v mySecret
```
#### Sample Terraform main.tf Azure:
```
variable "conjur_ssl_cert" {}
variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_host_id" {}
variable "conjur_authn_type" {}
variable "conjur_authn_service_id" {}

terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
      version = "~> 0"
    }
  }
}


provider "conjur" {
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = var.conjur_authn_type
  service_id    = var.conjur_authn_service_id
  host_id       = var.conjur_host_id
  ssl_cert      = var.conjur_ssl_cert
}
```
### GCP Authentication 

#### Sample Access Token from GCP
```
{
  "aud": "conjur/myorg/host/gcp-app/test-app",
  "azp": "105271527809661757734",
  "email": "411143357921-compute@developer.gserviceaccount.com",
  "email_verified": true,
  "exp": 1744734266,
  "google": {
    "compute_engine": {
      "instance_creation_timestamp": 1744730390,
      "instance_id": "1888435224091805695",
      "instance_name": "instance-20250415-151545",
      "project_id": "cyber-project-456915",
      "project_number": 411143357921,
      "zone": "us-central1-c"
    }
  },
  "iat": 1744730666,
  "iss": "https://accounts.google.com",
  "sub": "105271527809661757734"
}
```

#### Sample policy of GCP for OSS/Enterprise

Create a GCP authenticator policy and save it as authn-gcp.yml
```
- !policy
  id: conjur/authn-gcp
  body:
  - !webservice

  - !group 
    id: apps
    annotations:
      description: Group of hosts that can authenticate using the authn-gcp authenticator

  - !permit
    role: !group apps
    privilege: [ read, authenticate ]
    resource: !webservice

```
Load the policy into root
```
conjur policy load -f authn-gcp.yml -b root
```

Create a policy for host and save it as authn-gcp-hosts.yml
```
- !policy
  id: gcp-apps
  body:
    - !group
  
    - &hosts
      - !host
        id: test-app
        annotations:
          authn-gcp/project-id: cyber-project-456915
    - !grant
      role: !group
      members: *hosts
          
- !grant
  role: !group apps
  member: !group gcp-apps
```

Load the policy into conjur/authn-gcp
```
conjur policy load -b conjur/authn-gcp -f authn-gcp-hosts.yml
```

Create a policy for secret and save it as authn-gcp-secrets.yml
```
- !policy
  id: secrets
  body:
    - !group consumers

    - !variable test-variable

    - !permit
      role: !group consumers
      privilege: [ read, execute ]
      resource: !variable test-variable

- !grant
  role: !group secrets/consumers
  member: !group conjur/authn-gcp/gcp-apps
```

Load the policy into root
```
conjur policy load -f authn-gcp-secrets.yml -b root
```

#### Sample Policy of GCP for Conjur Cloud

Define the GCP Authenticator policy
```
- !webservice

- !group 
  id: apps
  annotations:
    description: Group of hosts that can authenticate using the authn-gcp authenticator

- !permit
  role: !group apps
  privilege: [ read, authenticate ]
  resource: !webservice

- !webservice
  id: status
  annotations:
    description: Status service to check that the authenticator is configured correctly

- !group
  id: operators
  annotations:
    description: Group of users who can check the status of the authenticator

- !permit
   role: !group operators
   privilege: [ read ]
   resource: !webservice status
```

Save the policy as authn-gcp.yml, and load it into conjur/authn-gcp

```
conjur policy load -f authn-gcp.yml -b conjur/authn-gcp
```
Enable the GCP authenticator
```
conjur authenticator enable --id authn-gcp
```
Define the Google Cloud service as a host in Conjur Cloud
```
- !policy
  id: gcp-apps
  body:
    - !group
  
    - &hosts
      - !host
        id: test-app
        annotations:
          authn-gcp/project-id: cyber-project-456915
    - !grant
      role: !group
      members: *hosts
```
Save the policy as authn-gcp-hosts.yaml, and load the policy file into any policy level under the data policy branch.
```
conjur policy load -b data/myspace -f authn-gcp-hosts.yaml
```
Create a policy that adds the host, or group of hosts, as a member of the group defined in the GCP Authenticator policy.
```
- !grant
  role: !group apps
  member: !group /data/myspace/gcp-apps
```
Save the policy as app-grants.yaml, and load the policy file into conjur/authn-gcp
```
conjur policy load -f app-grants.yaml -b conjur/authn-gcp
```
Assign the GCE group to the Safe's secrets and Copy the following and change my-safe to the name of your Safe synced from your PAM solution
```
# Give the hosts in the group permission to retrieve safe secrets
- !grant
  role: !group vault/my-safe/delegation/consumers
  member: !group myspace/gcp-apps
```
Save the policy as authn-gcp-secrets.yaml , and load the policy file into data
```
conjur policy load -f authn-gcp-secrets.yaml -b data
```
#### Sample Terraform main.tf for GCP:
```
variable "conjur_ssl_cert" {}
variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_authn_login" {}
variable "conjur_authn_type" {}

terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
      version = "~> 0"
    }
  }
}

provider "conjur" {
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = var.conjur_authn_type
  login         = conjur_authn_login
  ssl_cert      = var.conjur_ssl_cert
}
```
### Provider Configuration using JWT Authentication

#### Below section describes JWT authentication for conjur OSS/Enterprise

#### Sample policy of JWT for OSS/Enterprise
Define JWT Authentication Policy
```
- !policy
  id: conjur/authn-jwt/github
  body:
      - !webservice

      # jwks-uri for GitHub Actions: https://token.actions.githubusercontent.com/.well-known/jwks
      - !variable
        id: jwks-uri

      #In this example, "token-app-property" is set to "workflow"
      #Please refer to README.md for detailed policy and commands
      - !variable
        id: token-app-property

      #In this example, "identity-path" is set to "github-apps"
      #Please refer to README.md for detailed policy and commands
      - !variable
        id: identity-path

      #"issuer" for GitHub Actions: https://token.actions.githubusercontent.com
      - !variable
        id: issuer        

      #Group of applications that can authenticate using this JWT Authenticator
      - !group apps

      - !permit
        role: !group apps
        privilege: [read, authenticate]
        resource: !webservice

      - !webservice
        id: status

      #Group of users who can check the status of the JWT Authenticator
      - !group
        id: operators

      - !permit
        role: !group operators
        privilege: [read]
        resource: !webservice status
```
Save the policy as authn-jwt.yml and load it to root
```
conjur policy load -f authn-jwt.yml -b root
```
Enable the authenticator
```
authn-jwt/github
```
Populate the variables.
```
conjur variable set -i conjur/authn-jwt/github/token-app-property -v 'workflow'
conjur variable set -i conjur/authn-jwt/github/identity-path -v "github-apps"
conjur variable set -i conjur/authn-jwt/github/issuer -v "https://token.actions.githubusercontent.com"
conjur variable set -i conjur/authn-jwt/github/jwks-uri -v "https://token.actions.githubusercontent.com/.well-known/jwks"
```
Define a workload identity(host)
```
- !policy
  id: github-apps
  body:
      - !group

      - &hosts
        - !host
          id: conjur-action
          annotations:
              authn-jwt/github/repository: Nirupma-Verma/conjur-action
              authn-jwt/github/workflow_ref: Nirupma-Verma/conjur-action/.github/workflows/main.yml@refs/heads/master

      - !grant
        role: !group
        members: *hosts

- !grant
  role: !group conjur/authn-jwt/github/apps
  member: !group github-apps
```
Save the policy as authn-host.yml and load it to root.
```
conjur policy load -f authn-host.yml -b root
```
Define variables in Conjur to represent your secrets and give the workload permission to access to the secrets
```
- &devvariables
   - !variable Dev-Team-credential1
   - !variable Dev-Team-credential2
   - !variable Dev-Team-credential3
   - !variable Dev-Team-credential4

- !permit
  resource: *devvariables
  privileges: [ read, execute ]
  roles: !group github-apps
```
Save it as app-secret.yml and load it to root
```
conjur policy load -f app-secret.yml -b root
```

#### Below section describes JWT authentication for conjur cloud

#### Sample policy of JWT for Conjur cloud
Define JWT AUthenticator policy
```
- !policy
  id: github
  body:
      - !webservice

      # jwks-uri for GitHub Actions: https://token.actions.githubusercontent.com/.well-known/jwks
      - !variable
        id: jwks-uri

      #In this example, "token-app-property" is set to "workflow"
      #Please refer to README.md for detailed policy and commands
      - !variable
        id: token-app-property

      #In this example, "identity-path" is set to "data/github-apps"
      #Please refer to README.md for detailed policy and commands
      - !variable
        id: identity-path

      #"issuer" for GitHub Actions: https://token.actions.githubusercontent.com
      - !variable
        id: issuer        

      #Group of applications that can authenticate using this JWT Authenticator
      - !group apps

      - !permit
        role: !group apps
        privilege: [read, authenticate]
        resource: !webservice

      - !webservice
        id: status

      #Group of users who can check the status of the JWT Authenticator
      - !group
        id: operators

      - !permit
        role: !group operators
        privilege: [read]
        resource: !webservice status
```
Save the policy as authn-jwt.yml and and load the policy file into any policy level.
```
conjur policy load -f authn-jwt.yml -b conjur/authn-jwt
```
Enable the authenticator.
```
conjur authenticator enable --id authn-jwt/github
```
Populate the authenticator variables.
```
conjur variable set -i conjur/authn-jwt/azure/token-app-property -v 'workflow'
conjur variable set -i conjur/authn-jwt/$CONJUR_AUTHENTICATOR_ID/identity-path -v "data/github-apps"
conjur variable set -i conjur/authn-jwt/$CONJUR_AUTHENTICATOR_ID/issuer -v "https://token.actions.githubusercontent.com"
conjur variable set -i conjur/authn-jwt/$CONJUR_AUTHENTICATOR_ID/jwks-uri -v "https://token.actions.githubusercontent.com/.well-known/jwks"
```
Define a workload(host)
```
!policy
  id: github-apps
  body:
      - !group

      - &hosts
        - !host
          id: conjur-action
          annotations:
              authn-jwt/github/repository: Nirupma-Verma/conjur-action
              authn-jwt/github/workflow_ref: Nirupma-Verma/conjur-action/.github/workflows/main.yml@refs/heads/master

      - !grant
        role: !group
        members: *hosts
```
Save the policy as authn-host.yml and load it to data branch
```
conjur policy load -f authn-host.yml -b data
```
Grant the workload (host) permissions to the JWT authenticator's apps group.
```
- !grant
  roles:
     - !group apps
  members:
     - !group /data/github-apps
```
Save the policy as authn-grantapp.yaml and load it to conjur/authn-jwt/github branch
```
conjur policy load -f authn-grantapp.yaml -b conjur/authn-jwt/github
```
Give the workload access to secrets synced from your PAM solution.Assume that secrets in the ADO_Secret Safe have been synced to Conjur Cloud from your PAM solution
```
- !grant
  role: !group vault/ADO_Secret/delegation/consumers
  member: !group /data/github-apps
```
Save the policy as vault-permission.yaml and load it to data/vault/ADO_Secret branch.
```
conjur policy load -f vault-permission.yaml -b data/vault/ADO_Secret
```
#### Sample Terraform main.tf for JWT
```
variable "conjur_ssl_cert" {}
variable "conjur_appliance_url" {}
variable "conjur_account" {}
variable "conjur_authn_type" {}
variable "conjur_authn_service_id" {}
variable "conjur_secret_variable" {}


terraform {
  required_providers {
    conjur = {
      source  = "terraform.example.com/cyberark/conjur"
      version = "~> 0"
    }
  }
}

provider "conjur" {
  appliance_url = var.conjur_appliance_url
  account       = var.conjur_account
  authn_type    = var.conjur_authn_type
  service_id    = var.conjur_authn_service_id
  ssl_cert      = var.conjur_ssl_cert
  authn_jwt_token = "eybghh......."
}
```
### Fetch secrets

#### Preface

An important thing to keep in mind is that by design Terraform state files can contain
sensitive data (which may include credentials fetched by this plugin). Use Terraform's
recommendations found [here](https://www.terraform.io/docs/state/sensitive-data.html) to
protect these values where possible.

#### Example

_Note: If plan is being run manually, you will need to run `terraform init` first!_

```terraform
# main.tf
# ... provider configuration above

data "conjur_secret" "dbpass" {
  name = "my/shiny/dbpass"
}

output "dbpass_output" {
  value = "${data.conjur_secret.dbpass.value}"
  
  # Must mark this output value as sensitive for Terraform v0.15+,
  # because it's derived from a Conjur variable value that is declared
  # as sensitive.
  sensitive = true
}
```

Secrets like `data.conjur_secret.dbpass.value` can be used in any Terraform resources.

View an example Terraform manifest and Conjur policies in the
[test/](test/) directory in this project.

---

## Alternate Workflow with Summon

If this Terraform provider does not fit your needs, you can also use
[summon](https://github.com/cyberark/summon) with the
[summon-conjur](https://github.com/cyberark/summon-conjur) provider
to provide secrets to Terraform via environment variables.
The user running `terraform` must already be authenticated with Conjur.

Terraform's [`TF_VAR_name` syntax](https://www.terraform.io/docs/configuration/environment-variables.html#tf_var_name)
allows a user to set Terraform variables via environment variables.
To use Terraform with Summon, prefix the environment variable names in secrets.yml with `TF_VAR_`.

### Example

```terraform
# variables.tf
variable "access_key" {}
variable "secret_key" {}
```


```yaml
# secrets.yml
TF_VAR_access_key: !var aws/dev/sys_powerful/access_key_id
TF_VAR_secret_key: !var aws/dev/sys_powerful/secret_access_key
```

Run Terraform with Summon:

```sh
$ summon terraform apply
```

---

The current Terraform Secret Manager Provider supports API key authentication for retrieving secret. While API key-based authentication is secure, it introduces a secret-zero scenario, increases administrative overhead, and makes key rotations more difficult.
By enabling AWS IAM role, Azure and GCP authentication for Terraform Secret Manager Provider, the risk can be reduced by using short-lived tokens instead of static API keys, eliminating the need for manual key rotation. Leveraging AWS, Azure's and GCP resources for the generation of  access token, which can be used for more secure authentication with Secret Manager. The existing API key-based authentication functionality will remain operational.


## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and descriptions of our development workflows, please see our [contributing
guide][contrib].

[contrib]: CONTRIBUTING.md

## License

Copyright 2016-2022 CyberArk

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this software except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
