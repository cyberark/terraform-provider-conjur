#!/bin/bash -e

docker compose -f docker-compose.test.yml build
docker compose -f docker-compose.test.yml run -T \
  conjur_test bash -c "set -o pipefail; \
    echo 'Removing mocks package from coverage profile...'; \
    grep -v "/mocks" output/tests/c.out > output/tests/coverage.tmp && mv output/tests/coverage.tmp output/tests/c.out
    grep -v "/mocks" output/azure/c.out > output/azure/coverage.tmp && mv output/azure/coverage.tmp output/azure/c.out; \
    echo 'Merging coverage profiles...'; \
    gocovmerge output/tests/c.out output/azure/c.out > output/combined-c.out; \
    echo 'Coverage profile merged into output/combined-c.out.'; \
    echo 'Converting merged coverage profile to XML format...'; \
    gocov convert output/combined-c.out | gocov-xml > output/coverage.xml; \
    echo 'Coverage report generated at output/coverage.xml.'; \
    echo 'Combining verbose test outputs and converting to JUnit XML...'; \
    cat output/tests/junit.output output/azure/junit.output > output/junit.output; \
    go-junit-report < output/junit.output > output/junit.xml; \
    ls -l output/*.xml"
