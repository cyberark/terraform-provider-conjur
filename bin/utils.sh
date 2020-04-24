declare DOCKER_COMPOSE_ARGS

# shellcheck disable=SC2086
# DOCKER_COMPOSE_ARGS needs to stay unquoted to work 
function dockerCompose() {
  docker-compose $DOCKER_COMPOSE_ARGS "$@"
}

function conjurExec() {
  if [[ "$TARGET" == "oss" ]]; then
    dockerCompose exec -T conjur "$@"
  else
    dockerCompose exec -T conjur-server "$@"
  fi
}

function clientExec() {
  dockerCompose exec -T client "$@"
}

function terraformRun() {
  dockerCompose exec -T terraform sh -es "$@"
}
