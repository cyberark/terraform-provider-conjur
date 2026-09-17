# CLAUDE.md

Guidance for AI coding agents (Claude Code, Cursor, etc.) working in this repository.

## Overview

This is the **Terraform provider for CyberArk Secrets Manager (Conjur)** — `terraform-provider-conjur`, published as `cyberark/conjur` on the Terraform Registry. It lets Terraform authenticate to a Conjur OSS, Conjur Enterprise, or Conjur Cloud (SaaS) instance and manage/read Conjur resources: secrets, hosts, groups, policy branches, permissions, memberships, authenticators, and Secure Workload Access (SWA) trust domains/server groups/servers/node groups. It talks to Conjur over its HTTP API (via `github.com/cyberark/conjur-api-go` and a generated OpenAPI client) and is one of several official CyberArk Conjur integrations.

## Tech stack

- **Language:** Go (module `github.com/cyberark/terraform-provider-conjur`, requires Go >= 1.25, `go.mod` pins 1.26.2)
- **Framework:** [`terraform-plugin-framework`](https://github.com/hashicorp/terraform-plugin-framework) (the modern Terraform plugin SDK, not legacy SDKv2)
- **Release tooling:** GoReleaser (`.goreleaser.yml`), built/tested inside Docker via `docker compose`
- **Mocks:** generated with [mockery](https://github.com/vektra/mockery) (`.mockery.yaml`)
- **Docs:** generated with `tfplugindocs`-style tooling from `templates/` + `examples/` into `docs/`

## Build

```sh
go build -o terraform-provider-conjur main.go   # quick local build
./bin/build                                      # full containerized build via GoReleaser (docker compose)
```

Regenerate generated code/mocks after touching interfaces or the Conjur API client:

```sh
./bin/regenerate.sh   # runs `go generate` + mockery
```

Regenerate provider documentation after changing schemas/examples:

```sh
./bin/generate_docs
```

## Test

- **Unit tests** (`*_unit_test.go`, no external services): `go test ./...`
- **Acceptance/integration tests** (`*_test.go` under `internal/provider`, and Terraform configs under `tests/`) run against a real Conjur instance via Docker Compose:
  ```sh
  ./bin/test --target oss|enterprise|cloud --test-case api-key|jwt|iam|azure|gcp|cert
  ```
  This spins up Conjur (`docker-compose*.yml`), loads fixture policy from `conf/policy/<test-case>/`, runs Terraform plans against `tests/<test-case>/`, and (for `api-key`) additionally runs per-resource CRUD/import tests via `./bin/run_resource_tests` against `tests/resources/<resource>/{create,update}`.
- Enterprise tests require access to CyberArk's internal Docker registry (must be logged in).

## Repo structure

- `main.go` — provider entrypoint; registers `internal/provider` with `terraform-plugin-framework`'s `providerserver`.
- `internal/provider/` — all resources, data sources, and the ephemeral resource. Files follow `resource_<name>.go` / `data_source_<name>.go`, each with `_test.go` (acceptance) and `_unit_test.go` (unit) siblings.
- `internal/conjur/` — Conjur API client wrapper; `internal/conjur/api/client_v2.gen.go` is **generated** (oapi-codegen) — edit the OpenAPI spec / regenerate, don't hand-edit.
- `internal/policy/` — Conjur policy YAML handling.
- `internal/swa/` — Secure Workload Access (SWA) API client and models, used by the `conjur_swa_*` resources.
- `**/mocks/` — mockery-generated mocks; regenerate via `./bin/regenerate.sh`, don't hand-edit.
- `docs/` — generated Terraform Registry documentation; regenerate via `./bin/generate_docs`, don't hand-edit directly.
- `templates/`, `examples/` — source-of-truth inputs for doc generation (`templates/*.tmpl`, `examples/{resources,data-sources,provider}/*.tf`).
- `tests/` — integration Terraform configs, organized by authn method (`api-key`, `jwt`, `iam`, `azure`, `gcp`, `cert`) and per-resource CRUD tests (`tests/resources/<resource>/{create,update}`).
- `conf/policy/` — Conjur policy fixtures loaded before integration tests, one subfolder per authn method plus `common/`.
- `demo/` — standalone example environment (docker-compose + `.tf` files) showing end-to-end provider usage; not part of the test suite.
- `bin/` — dev scripts: `build`, `test`, `run_resource_tests`, `regenerate.sh`, `generate_docs`, `codecoverage.sh`, `utils.sh`.
- `Dockerfile.goreleaser` / `Dockerfile.terraform` / `Dockerfile.testfile` / `Dockerfile.tools` — images used by `docker-compose*.yml` for building and testing.
- `.goreleaser.yml`, `terraform-registry-manifest.json` — release/publish config for the Terraform Registry.

## Conventions & gotchas

- **Resources are SaaS-only in places**: `conjur_host`, `conjur_secret`, and all `conjur_swa_*` resources only work against Conjur Cloud (SaaS), not OSS/Enterprise — check the doc comments/README before assuming a resource works everywhere.
- **Write-only attributes**: `conjur_secret` supports a write-only `value_wo` attribute that must never be persisted to state — preserve this behavior if touching secret import/read logic.
- Never hand-edit generated files: `internal/conjur/api/client_v2.gen.go`, anything under `mocks/`, and everything in `docs/` — regenerate via the `bin/` scripts instead.
- The `replace github.com/cyberark/conjur-api-go => ... latest` line in `go.mod` is rewritten by the automated release process — do not remove the marker comment above it.
- Integration tests require Docker and network access to pull Conjur images; they are not run by plain `go test` — use `./bin/test`.
