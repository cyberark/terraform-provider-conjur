declare DOCKER_COMPOSE_ARGS

# shellcheck disable=SC2086
# DOCKER_COMPOSE_ARGS needs to stay unquoted to work 
function dockerCompose() {
  docker-compose $DOCKER_COMPOSE_ARGS "$@"
}

function conjurExec() {
  dockerCompose exec -T conjur-server "$@"
}

function clientExec() {
  dockerCompose exec -T client "$@"
}

function terraformRun() {
  dockerCompose exec -T terraform sh -es "$@"
}
