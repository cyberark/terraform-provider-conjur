resource "docker_container" "postgres" {
  name = "postgres"
  image = "${docker_image.postgres.latest}"
  env = ["POSTGRES_PASSWORD=${data.conjur_secret.admin-password.value}"]
  networks = ["${docker_network.demo.name}"]
}

resource "docker_image" "postgres" {
  name = "postgres:10"
}
