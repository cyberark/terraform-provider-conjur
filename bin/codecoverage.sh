#!/bin/bash -e

JWT_TOKEN=""
TOKENGCP="gcp/token"
export GCP_TOKEN=$(cat $TOKENGCP)
TESTCASE="${1:-TestAPISecretDataSource|TestJWTSecretDataSource}"

if [ -z "$TESTCASE" ]; then
    output_dir="output/tests" 
elif [ "$TESTCASE" == "TestAzureSecretDataSource" ]; then
    output_dir="output/azure"
elif [ "$TESTCASE" == "TestIAMSecretDataSource" ]; then
    output_dir="output/aws"
else
    output_dir="output/tests"
fi

mkdir -p "$output_dir"


./bin/test -t oss -tc jwt -jwt true
export JWT_TOKEN=$(cat jwt_token)
export CONJUR_CERT_CONTENT=$(cat conf/https_config/ca.crt)

docker compose -f docker-compose.test.yml build
docker compose -f docker-compose.test.yml run -T\
  -e output_dir="$output_dir" \
  conjur_test bash -c "set -o pipefail;
    echo \"Go version: \$(go version)\";
    TF_ACC=1 TF_LOG=debug go test -run \"^(${TESTCASE})\$\" ./internal/provider -coverprofile=\"\$output_dir/c.out\" -v ./... | tee \"\$output_dir/junit.output\";
    exit_code=\$?;
    echo \"Tests finished - aggregating results...\";
    cat \"\$output_dir/junit.output\" | go-junit-report > \"\$output_dir/junit.xml\";
    gocov convert \"\$output_dir/c.out\" | gocov-xml > \"\$output_dir/coverage.xml\";
    ls -l \"\$output_dir\";
    [ \"\$exit_code\" -eq 0 ]"
