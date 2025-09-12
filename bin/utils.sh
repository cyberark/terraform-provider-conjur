#!/bin/bash
declare DOCKER_COMPOSE_ARGS

# shellcheck disable=SC2086
# DOCKER_COMPOSE_ARGS needs to stay unquoted to work 
function docker_compose() {
  docker compose $DOCKER_COMPOSE_ARGS "$@"
}

function conjur_exec() {
  if [[ "$TARGET" == "oss" ]]; then
    docker_compose exec -T conjur "$@"
  else
    docker_compose exec -T conjur-server "$@"
  fi
}

function client_exec() {
  docker_compose exec -T client "$@"
}

function terraform_exec() {
  docker_compose exec -T terraform sh -ec "$@"
}

function url_encode() {
  printf '%s' "$1" | jq -sRr @uri
}

function check_target() {
  case "$TARGET" in
    "oss")
      export DOCKER_COMPOSE_ARGS="-f docker-compose.oss.yml -f docker-compose.yml"
      export CONJUR_WAIT_COMMAND="/opt/conjur-server/bin/conjurctl wait"
      ;;
    "enterprise")
      export DOCKER_COMPOSE_ARGS="-f docker-compose.enterprise.yml -f docker-compose.yml"
      export CONJUR_WAIT_COMMAND="/opt/conjur/evoke/bin/wait_for_conjur"
      ;;
    "cloud")

      ;;
    *)
      echo "> Error: '$TARGET' is not a supported target"
      exit 1
      ;;
  esac
}
