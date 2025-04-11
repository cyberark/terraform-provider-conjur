#!/bin/bash -e

#generate output directory locally.
# output_dir="./output"
# mkdir "$output_dir"

output_dir="output"
mkdir $output_dir

docker compose -f docker-compose.test.yml build
docker compose -f docker-compose.test.yml run \
  conjur_test bash -c 'set -o pipefail;
           echo "Go version: $(go version)"
           output_dir="./output"
           TF_ACC=1 go test -coverprofile="$output_dir/c.out" -v ./... | tee "$output_dir/junit.output";
           exit_code=$?;
           echo "Tests finished - aggregating results...";
           cat "$output_dir/junit.output" | go-junit-report > "$output_dir/junit.xml";
           gocov convert "$output_dir/c.out" | gocov-xml > "$output_dir/coverage.xml";
           [ "$exit_code" -eq 0 ]' || { echo "Tests failed"; exit 1; } 