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
    stage('Build artifacts') {
      steps {
        sh './bin/build'
        archiveArtifacts artifacts: "dist/*.tar.gz,dist/*.zip,dist/*.txt,dist/*.rb", fingerprint: true
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
