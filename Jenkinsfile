#!/usr/bin/env groovy
  // Automated release, promotion and dependencies
properties([
  // Include the automated release parameters for the build
  release.addParams(),
  // Dependencies of the project that should trigger builds
  dependencies([])
])

// Performs release promotion.  No other stages will be run
if (params.MODE == "PROMOTE") {
  release.promote(params.VERSION_TO_PROMOTE) { infrapool
  }
  return
}

pipeline {
  agent { label 'conjur-enterprise-common-agent' }

  options {
    timestamps()
    buildDiscarder(logRotator(daysToKeepStr: '30'))
  }

  triggers {
    cron(getDailyCronString())
  }

  
  stages {
    stage('Get InfraPool ExecutorV2 Agent') {
      steps {
        script {
          // Request InfraPool
          INFRAPOOL_EXECUTORV2_AGENT_0 = getInfraPoolAgent.connected(type: "ExecutorV2", quantity: 1, duration: 1)[0]
        }
      }
    }

    stage('Get latest upstream dependencies') {
      steps {
        script {
          withCredentials([usernamePassword(credentialsId: 'jenkins_ci_token', usernameVariable: 'GITHUB_USER', passwordVariable: 'TOKEN')]) {
            sh './bin/updateGoDependencies.sh -g "${WORKSPACE}/go.mod"'
          }
          // Copy the vendor directory onto infrapool
          INFRAPOOL_EXECUTORV2_AGENT_0.agentPut from: "vendor", to: "${WORKSPACE}"
          INFRAPOOL_EXECUTORV2_AGENT_0.agentPut from: "go.*", to: "${WORKSPACE}"
        }
      }
    }

    stage('Validate') {
      parallel {
        stage('Changelog') {
          steps { parseChangelog(INFRAPOOL_EXECUTORV2_AGENT_0) }
        }
      }
    }

    stage('Build artifacts') {
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/build'
          INFRAPOOL_EXECUTORV2_AGENT_0.agentArchiveArtifacts artifacts: "dist/*.tar.gz,dist/*.zip,dist/*.txt,dist/*.rb,dist/*_SHA256SUMS", fingerprint: true
        }
      }
    }
    stage('Run integration tests (OSS)') {
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test oss'
        }
      }
    }
    stage('Run integration tests (Conjur 5 Enterprise)') {
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh './bin/test enterprise'
        }
      }
    }
    stage('Run integration tests (cloud)'){
      steps {
        script {
          INFRAPOOL_EXECUTORV2_AGENT_0.agentSh 'summon ./bin/test cloud'
        }
      }
    }
  }

  post {
    always {
      script {
        releaseInfraPoolAgent(".infrapool/release_agents")
      }
    }
  }
}
