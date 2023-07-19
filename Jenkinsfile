#!/usr/bin/env groovy

pipeline {
  agent { label 'executor-v2' }

  options {
    timestamps()
    buildDiscarder(logRotator(daysToKeepStr: '30'))
  }

  triggers {
    cron(getDailyCronString())
  }

  stages {
    stage('Validate') {
      parallel {
        stage('Changelog') {
          steps { parseChangelog() }
        }
      }
    }

    stage('Get latest upstream dependencies') {
      steps {
        updateGoDependencies('${WORKSPACE}/go.mod')
      }
    }

    stage('Build artifacts') {
      steps {
        sh './bin/build'
        archiveArtifacts artifacts: "dist/*.tar.gz,dist/*.zip,dist/*.txt,dist/*.rb,dist/*_SHA256SUMS", fingerprint: true
      }
    }

    stage('Run Unit Tests') {
          steps {
            sh './bin/unit-test.sh'
          }
    }

    stage('Run integration tests (OSS)') {
      steps {
        sh './bin/test oss'
      }
    }
    stage('Run integration tests (Conjur 5 Enterprise)') {
      steps {
        sh './bin/test enterprise'
      }
    }
  }

  post {
    always {
      cleanupAndNotify(currentBuild.currentResult)
    }
  }
}
