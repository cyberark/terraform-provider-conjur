#!/usr/bin/env groovy

pipeline {
  agent { label 'executor-v2' }

  options {
    timestamps()
    buildDiscarder(logRotator(daysToKeepStr: '30'))
  }

  stages {
    stage('Build artifacts') {
      steps {
        sh './bin/build'
        archiveArtifacts artifacts: "dist/*.tar.gz,dist/*.zip", fingerprint: true
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
