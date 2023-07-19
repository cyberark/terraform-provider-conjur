#!/bin/bash -e

docker-compose -f docker-compose.test.yml build
docker-compose -f docker-compose.test.yml run conjur_test bash -c "cd conjur && go test -v";