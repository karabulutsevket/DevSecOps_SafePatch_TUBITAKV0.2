// Requires a trusted Linux client agent with this project/venv prepared.
// Credentials: safepatch-submit-token (secret text). Human approval remains in SafePatch.
pipeline {
  agent { label 'trusted-safepatch-client' }
  options { timeout(time: 40, unit: 'MINUTES'); disableConcurrentBuilds() }
  environment { SAFEPATCH_URL = 'http://127.0.0.1:8100' }
  stages {
    stage('Start remediation') {
      steps {
        withCredentials([string(credentialsId: 'safepatch-submit-token', variable: 'SAFEPATCH_TOKEN')]) {
          sh '.venv/bin/python -m safepatch.cli start sql-01 --scanner semgrep > job.json'
          script {
            env.SAFEPATCH_JOB = sh(script: '.venv/bin/python -c "import json; print(json.load(open(\"job.json\"))[\"id\"])"', returnStdout: true).trim()
          }
        }
      }
    }
    stage('Wait and publish evidence') {
      steps {
        withCredentials([string(credentialsId: 'safepatch-submit-token', variable: 'SAFEPATCH_TOKEN')]) {
          sh '.venv/bin/python -m safepatch.cli wait "$SAFEPATCH_JOB" > result.json'
          sh '.venv/bin/python -m safepatch.cli evidence "$SAFEPATCH_JOB" --out jenkins-evidence'
          sh '.venv/bin/python -c "import json,sys; sys.exit(0 if json.load(open(\"result.json\"))[\"status\"]==\"awaiting_review\" else 1)"'
        }
        archiveArtifacts artifacts: 'job.json,result.json,jenkins-evidence/**/*', fingerprint: true
      }
    }
    stage('Human review in SafePatch') {
      steps {
        echo 'Open the local SafePatch review screen. Approve using your own reviewer credential, then deploy using the separate deployer credential. Jenkins has no review credential.'
        // A Jenkins input username is deliberately not accepted as service authentication.
        withCredentials([string(credentialsId: 'safepatch-submit-token', variable: 'SAFEPATCH_TOKEN')]) {
          sh '.venv/bin/python scripts/await_deployment.py "$SAFEPATCH_JOB" --timeout 900'
        }
      }
    }
  }
  post {
    aborted {
      script {
        if (env.SAFEPATCH_JOB) {
          withCredentials([string(credentialsId: 'safepatch-submit-token', variable: 'SAFEPATCH_TOKEN')]) {
            sh '.venv/bin/python -m safepatch.cli cancel "$SAFEPATCH_JOB"'
          }
        }
      }
    }
  }
}
