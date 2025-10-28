#!/usr/bin/env groovy

// 'product-pipelines-shared-library' draws from DevOps/product-pipelines-shared-library repository.
// 'conjur-enterprise-sharedlib' draws from Conjur-Enterprise/jenkins-pipeline-library repository.
@Library(['product-pipelines-shared-library', 'conjur-enterprise-sharedlib']) _

  // Automated release, promotion and dependencies
properties([
  // Include the automated release parameters for the build
  release.addParams(),
  // Dependencies of the project that should trigger builds
  dependencies([])
])

// Performs release promotion.  No other stages will be run
if (params.MODE == "PROMOTE") {
  release.promote(params.VERSION_TO_PROMOTE) { infrapool, sourceVersion, targetVersion, assetDirectory ->
    // Gather the SUMS file to sign
    sums = "*SHA256SUMS"
    infrapool.agentGet from: "${assetDirectory}/${sums}", to: "./"
    sumFile = sh(script: "ls ${sums}", returnStdout: true).trim()
    // Create .tar for signing
    sh "mv ${sumFile} ${sumFile}.tar"
    signArtifacts patterns: ["${sumFile}.tar"]
    // Rename the sig file
    sh "mv ${sumFile}.tar.sig ${sumFile}.sig"
    // Copy back to assetDirectory
    sigLocation = pwd() + "/${sumFile}.sig"
    infrapool.agentPut from: "${sigLocation}", to: "${assetDirectory}"
  }

  // Copy Github Enterprise release to Github
  release.copyEnterpriseRelease(params.VERSION_TO_PROMOTE)
  return
}

pipeline {
  agent { label 'conjur-enterprise-common-agent' }

  options {
    timestamps()
    buildDiscarder(logRotator(daysToKeepStr: '30'))
  }

  environment {
    MODE = release.canonicalizeMode()
  }

  triggers {
    parameterizedCron("""
      ${getDailyCronString("%TEST_CLOUD=true")}
      ${getWeeklyCronString("H(1-5)", "%MODE=RELEASE")}
    """)
  }

  parameters {
    booleanParam(name: 'TEST_CLOUD', defaultValue: true, description: 'Run integration tests against a Conjur Cloud tenant')
  }

  stages {
    stage('Scan for internal URLs') {
      steps {
        script {
          detectInternalUrls()
        }
      }
    }

    stage('Get InfraPool ExecutorV2 Agent') {
      steps {
        script {
          // Request InfraPool
          INFRAPOOL_EXECUTORV2_AGENT_0 = getInfraPoolAgent.connected(type: "ExecutorV2", quantity: 1, duration: 1)[0]
          INFRAPOOL_AZURE_EXECUTORV2_AGENT_0 = getInfraPoolAgent.connected(type: "AzureExecutorV2", quantity: 1, duration: 1)[0]
          INFRAPOOL_GCP_EXECUTORV2_AGENT_0 = getInfraPoolAgent.connected(type: "GcpExecutorV2", quantity: 1, duration: 1)[0]
        }
      }
    }

    // Generates a VERSION file based on the current build number and latest version in CHANGELOG.md
    stage('Validate changelog and set version') {
      steps {
        updateVersion(INFRAPOOL_EXECUTORV2_AGENT_0, "CHANGELOG.md", "${BUILD_NUMBER}")
        updateVersion(INFRAPOOL_AZURE_EXECUTORV2_AGENT_0, "CHANGELOG.md", "${BUILD_NUMBER}")
        updateVersion(INFRAPOOL_GCP_EXECUTORV2_AGENT_0, "CHANGELOG.md", "${BUILD_NUMBER}")
      }
    }

    stage('Get latest upstream dependencies') {
      steps {
        script {
          updatePrivateGoDependencies("${WORKSPACE}/go.mod")
          // Copy the vendor directory onto infrapool (every agent that runs the build script)
          INFRAPOOL_EXECUTORV2_AGENT_0.agentPut from: "vendor", to: "${WORKSPACE}"
          INFRAPOOL_EXECUTORV2_AGENT_0.agentPut from: "go.*", to: "${WORKSPACE}"
          INFRAPOOL_AZURE_EXECUTORV2_AGENT_0.agentPut from: "vendor", to: "${WORKSPACE}"
          INFRAPOOL_AZURE_EXECUTORV2_AGENT_0.agentPut from: "go.*", to: "${WORKSPACE}"
        }
      }
    }

    stage('Build artifacts') {
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/build'
          INFRAPOOL_AZURE_EXECUTORV2_AGENT_0.agentSh './bin/build'
        }
      }
    }

    stage('Generate GCP token') {
      steps {
        script {
          INFRAPOOL_GCP_EXECUTORV2_AGENT_0.agentSh './bin/get_gcp_token.sh host/data/gcp-apps/test-app conjur'
          INFRAPOOL_GCP_EXECUTORV2_AGENT_0.agentStash name: 'token-out', includes: 'gcp/*'
        }
      }
    }

    stage('Run Code Coverage'){
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentUnstash name: 'token-out'
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh 'summon ./bin/codecoverage.sh'
          INFRAPOOL_EXECUTORV2_AGENT_0.agentStash name: 'xml-out1', includes: 'output/tests/*'
          INFRAPOOL_AZURE_EXECUTORV2_AGENT_0.agentSh 'summon ./bin/codecoverage.sh TestAzureSecretDataSource'
          INFRAPOOL_AZURE_EXECUTORV2_AGENT_0.agentStash name: 'xml-out2', includes: 'output/azure/*'
        } 
      }
    }

    stage('Generate code coverage xml'){
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentUnstash name: 'xml-out1'
          INFRAPOOL_EXECUTORV2_AGENT_0.agentUnstash name: 'xml-out2'
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/generate_xml.sh'
          INFRAPOOL_EXECUTORV2_AGENT_0.agentStash name: 'output-xml', includes: 'output/*.xml'

        } 
      }
    }
    
    stage('Run integration tests (OSS) for Api Key') {
      environment {
        INFRAPOOL_REGISTRY_URL = "registry.tld"
      }
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test -t oss -tc api-key'
        }
      }
    }

    stage('Run integration tests (OSS) for JWT') {
      environment {
        INFRAPOOL_REGISTRY_URL = "registry.tld"
      }
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test -t oss -tc jwt'
        }
      }
    }

    stage('Run integration tests (OSS) for IAM') {
      environment {
        INFRAPOOL_REGISTRY_URL = "registry.tld"
      }
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test -t oss -tc iam'
        }
      }
    }

    stage('Run integration tests (OSS) for Azure') {
      environment {
        INFRAPOOL_REGISTRY_URL = "registry.tld"
      }
      steps {
        script {
          INFRAPOOL_AZURE_EXECUTORV2_AGENT_0.agentSh 'summon ./bin/test -t oss -tc azure'
        }
      }
    }
    
    stage('Run integration tests (OSS) for GCP') {
      environment {
        INFRAPOOL_REGISTRY_URL = "registry.tld"
      }
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentUnstash name: 'token-out'
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test -t oss -tc gcp'
        }
      }
    }

    stage('Run Conjur Cloud tests') {
      when {
        expression { params.TEST_CLOUD }
      }
      stages {
        stage('Create a Tenant') {
          steps {
            script {
              TENANT = getConjurCloudTenant()
            }
          }
        }
        stage('Authenticate') {
          steps {
            script {
              def id_token = getConjurCloudTenant.tokens(
                infrapool: INFRAPOOL_EXECUTORV2_AGENT_0,
                identity_url: "${TENANT.identity_information.idaptive_tenant_fqdn}",
                username: "${TENANT.login_name}"
              )

              def conj_token = getConjurCloudTenant.tokens(
                infrapool: INFRAPOOL_EXECUTORV2_AGENT_0,
                conjur_url: "${TENANT.conjur_cloud_url}",
                identity_token: "${id_token}"
                )

              env.conj_token = conj_token
            }
          }
        }

        stage('Run integration tests (Conjur Cloud Tenant) for Api Key') {
          environment {
            INFRAPOOL_CONJUR_APPLIANCE_URL="${TENANT.conjur_cloud_url}"
            INFRAPOOL_CONJUR_AUTHN_LOGIN="${TENANT.login_name}"
            INFRAPOOL_CONJUR_AUTHN_TOKEN="${env.conj_token}"
          }
          steps {
            script {
              INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test -t cloud -tc api-key'
            }
          }
        }
        
        stage('Run integration tests (Conjur Cloud Tenant) for JWT') {
          environment {
            INFRAPOOL_CONJUR_APPLIANCE_URL="${TENANT.conjur_cloud_url}"
            INFRAPOOL_CONJUR_AUTHN_LOGIN="${TENANT.login_name}"
            INFRAPOOL_CONJUR_AUTHN_TOKEN="${env.conj_token}"
          }
          steps {
            script {
              INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test -t cloud -tc jwt'
            }
          }
        }

        stage('Run integration tests (Conjur Cloud Tenant) for IAM') {
          environment {
            INFRAPOOL_CONJUR_APPLIANCE_URL="${TENANT.conjur_cloud_url}"
            INFRAPOOL_CONJUR_AUTHN_LOGIN="${TENANT.login_name}"
            INFRAPOOL_CONJUR_AUTHN_TOKEN="${env.conj_token}"
          }
          steps {
            script {
              INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test -t cloud -tc iam'
            }
          }
        }

        stage('Run integration tests (Conjur Cloud Tenant) for Azure') {
          environment {
            INFRAPOOL_CONJUR_APPLIANCE_URL="${TENANT.conjur_cloud_url}"
            INFRAPOOL_CONJUR_AUTHN_LOGIN="${TENANT.login_name}"
            INFRAPOOL_CONJUR_AUTHN_TOKEN="${env.conj_token}"
          }
          steps {
            script {
              INFRAPOOL_AZURE_EXECUTORV2_AGENT_0.agentSh 'summon ./bin/test -t cloud -tc azure'
            }
          }
        }

        stage('Generate GCP token for Conjur Cloud') {
          steps {
            script{
              INFRAPOOL_GCP_EXECUTORV2_AGENT_0.agentSh './bin/get_gcp_token.sh host/data/gcp-apps/test-app conjur'
              INFRAPOOL_GCP_EXECUTORV2_AGENT_0.agentStash name: 'token-out-cloud', includes: 'gcp/*'
            }
          }
        }

        stage('Run integration tests (Conjur Cloud Tenant) for GCP') {
          environment {
            INFRAPOOL_CONJUR_APPLIANCE_URL="${TENANT.conjur_cloud_url}"
            INFRAPOOL_CONJUR_AUTHN_LOGIN="${TENANT.login_name}"
            INFRAPOOL_CONJUR_AUTHN_TOKEN="${env.conj_token}"
          }
          steps {
            script {
              INFRAPOOL_EXECUTORV2_AGENT_0.agentUnstash name: 'token-out-cloud'
              INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test -t cloud -tc gcp'
            }
          }
        }
      }
      post {
        always {
          script {
            deleteConjurCloudTenant("${TENANT.id}")
          }
        }
      }
    }

    stage('Release') {
      when {
        expression {
          MODE == "RELEASE"
        }
      }
      steps {
        script {
          release(INFRAPOOL_EXECUTORV2_AGENT_0) { billOfMaterialsDirectory, assetDirectory, toolsDirectory ->
            // Publish release artifacts to all the appropriate locations
            // Copy any artifacts to assetDirectory to attach them to the Github release
            INFRAPOOL_EXECUTORV2_AGENT_0.agentSh "cp -r dist/*.zip dist/*_SHA256SUMS ${assetDirectory}"
            // Create Go module SBOM
            INFRAPOOL_EXECUTORV2_AGENT_0.agentSh """export PATH="${toolsDirectory}/bin:${PATH}" && go-bom --tools "${toolsDirectory}" --go-mod ./go.mod --image "golang" --output "${billOfMaterialsDirectory}/go-mod-bom.json" """
          }
        }
      }  
    }
  }
  
  
  post {
    always {
      unstash 'output-xml'
      junit 'output/junit.xml'
      cobertura autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: 'output/coverage.xml', conditionalCoverageTargets: '30, 0, 0', failUnhealthy: false, failUnstable: false, lineCoverageTargets: '30, 0, 0', maxNumberOfBuilds: 0, methodCoverageTargets: '30, 0, 0', onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false
      codacy action: 'reportCoverage', filePath: "output/coverage.xml"
      releaseInfraPoolAgent(".infrapool/release_agents") 
      // Resolve ownership issue before running infra post hook
      sh 'git config --global --add safe.directory ${PWD}'
      infraPostHook()
    }
  }
}
