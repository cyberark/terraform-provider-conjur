#!/bin/bash
set -exo pipefail

JWT_TOKEN=""
TOKENGCP="gcp/token"
export GCP_TOKEN=$(cat $TOKENGCP)

./bin/test -t oss -tc jwt -jwt true || true
export JWT_TOKEN=$(cat jwt_token)
export CONJUR_CERT_CONTENT=$(cat conf/https_config/ca.crt)
export TF_SECRET_VALUE="nirupma" # Do not try to change this value
export TF_JWT_SECRET_VALUE="SECRETXcLhn23MJcimV"


TESTCASE="$1"
output_dir="output/tests"

# Set output directory based on test case
case "$TESTCASE" in
  *TestAzureSecretDataSource*)
    output_dir="output/azure"
    ;;
  *TestIAMSecretDataSource*)
    output_dir="output/aws"
    ;;
esac

mkdir -p "$output_dir"

docker compose -f docker-compose.test.yml build

# Initialize a list of test cases to run (exclude Azure/IAM by default since they require extra setup)
if [ -z "${TESTCASE:-}" ]; then
  echo "All tests will be run except Azure/IAM..."
  TESTCASE=$(docker compose -f docker-compose.test.yml run -T conjur_test \
    bash -c "go test ./internal/... -list . | grep '^Test' | \
      grep -Ev 'TestAzureSecretDataSource|TestIAMSecretDataSource' | \
      paste -sd '|' -")
fi

docker compose -f docker-compose.test.yml run -T \
  -e output_dir="$output_dir" \
  conjur_test bash -c "
    echo \"Go version: \$(go version)\";
    TF_ACC=1 TF_LOG=debug go test -run \"^(${TESTCASE})\$\" ./internal/... -coverprofile=\"\$output_dir/c.out\" -v | tee \"\$output_dir/junit.output\";
    exit_code=\$?;
    echo \"Tests finished - aggregating results...\";
    cat \"\$output_dir/junit.output\" | go-junit-report > \"\$output_dir/junit.xml\";
    gocov convert \"\$output_dir/c.out\" | gocov-xml > \"\$output_dir/coverage.xml\";
    [ \"\$exit_code\" -eq 0 ]
    "
