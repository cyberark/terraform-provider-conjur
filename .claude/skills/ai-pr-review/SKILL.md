---
name: ai-pr-review
description: Automated audit of code changes before opening a Pull Request against this repo (terraform-provider-conjur, the official Go Terraform provider for CyberArk Secrets Manager/Conjur, published as cyberark/conjur). Analyzes the diff against the base branch, checks compliance with CyberArk standards (architecture, security, quality) and this repo's own CLAUDE.md conventions, and generates a PR_REVIEW_REPORT.md ready to paste into the PR description. Use before every commit that finalizes a task, or when the user writes "@ai-pr-review run analysis and generate report".
---

# AI PR Review

Automated audit of code changes before opening a Pull Request. The skill analyzes the diff, checks compliance with the CyberArk and repo-specific conventions used in `terraform-provider-conjur`, and generates a report ready to paste into the PR description.

## Workflow

### 1. Context Extraction

- Run `git diff` against the base branch (`main`).
- Identify the changed components (see `CLAUDE.md` for the full layout):
  - `internal/provider/` — resources/data sources/ephemeral resources (`resource_<name>.go`, `data_source_<name>.go`), each with `_test.go` (acceptance) and `_unit_test.go` (unit) siblings
  - `internal/conjur/` — Conjur API client wrapper; `internal/conjur/api/client_v2.gen.go` is generated (oapi-codegen)
  - `internal/policy/` — Conjur policy YAML handling
  - `internal/swa/` — Secure Workload Access (SWA) client/models for `conjur_swa_*` resources
  - `docs/`, `templates/`, `examples/` — generated Registry docs and their source templates

### 2. Multi-Persona Analysis

- **Architect**:
  - Any hand-edit of `internal/conjur/api/client_v2.gen.go`, anything under `mocks/`, or anything under `docs/` is a hard blocker — these are generated (`./bin/regenerate.sh`, `./bin/generate_docs`); the PR must instead touch the OpenAPI spec/generator config or `templates/`+`examples/`.
  - New resources/data sources should follow the existing `terraform-plugin-framework` pattern (not legacy SDKv2), matching the structure of existing `resource_*.go`/`data_source_*.go` files.
  - Check whether a new/changed resource is SaaS-only (like `conjur_host`, `conjur_secret`, all `conjur_swa_*`) vs. works against OSS/Enterprise too, and that this is documented correctly (doc comments + generated docs).
- **Security**:
  - No hardcoded Conjur credentials, API keys, or certs in provider code, `tests/`, `conf/policy/`, or `examples/`.
  - `conjur_secret`'s write-only `value_wo` attribute must never be persisted to Terraform state — flag any change to secret import/read logic that risks leaking a secret value into state.
  - Do not remove or alter the `// DO NOT EDIT` / automated-release marker comment above the `replace github.com/cyberark/conjur-api-go => ... latest` line in `go.mod` — it's rewritten by the release process.
- **Quality**:
  - New provider logic needs both a unit test (`*_unit_test.go`, no external services, `go test ./...`) and, where it touches real Conjur behavior, an acceptance test (`*_test.go` under `internal/provider`) runnable via `./bin/test --target oss|enterprise|cloud --test-case <case>`.
  - New/changed resources should have corresponding CRUD fixtures under `tests/resources/<resource>/{create,update}` when they support import/update.
  - Mocks (mockery-generated, `.mockery.yaml`) must be regenerated via `./bin/regenerate.sh`, never hand-edited.

### 3. Standard Compliance

- Go version follows `go.mod` (currently >= 1.25, pinned to 1.26.2) — flag mismatches with CI/Dockerfiles if bumped inconsistently.
- Provider documentation (`docs/`) must be regenerated via `./bin/generate_docs` after any schema/example change — a PR that changes `internal/provider/*.go` schemas without corresponding `docs/` changes should be flagged.
- `CHANGELOG.md` should reflect release-worthy changes, consistent with the GoReleaser-based release process (`.goreleaser.yml`).

### 4. Report Generation

Generate `PR_REVIEW_REPORT.md` **fully filled in** — never leave a `<placeholder>` in the final file. Derive each field automatically:

- **One-line summary**: one imperative-mood sentence describing what the diff does.
- **Desired Outcome**: if the branch name or commit messages reference a ticket/issue, pull context from it (e.g. `gh issue view <n>` for a `#<n>` reference); otherwise infer the motivating problem directly from what the diff changes.
- **Implemented Changes**: build this directly from the actual `git diff` and the Multi-Persona Analysis findings (step 2) — what changed, why, and how a reviewer should verify it (manual/integration steps if any). State screenshots as "N/A" unless the diff touches UI.
- **Connected Issue/Story**: scan the current branch name and the commit messages on this branch for a ticket pattern like `[A-Z]+-\d+` (e.g. `CP-26179`, `CNJR-1234`) and use the first match as the "CyberArk internal issue ID". If a GitHub issue number is referenced (`#123` in a branch name or commit message), use it for "Resolves #123" — otherwise omit that line entirely rather than leaving a placeholder.
- **Definition of Done** — tick exactly one box per subsection based on what the diff actually contains, never by default:
  - *Changelog*: tick "CHANGELOG has been updated" only if `CHANGELOG.md` (or equivalent) is part of the diff; tick "does not require a CHANGELOG update" only if the change has no user-facing effect.
  - *Test coverage*: tick "includes new tests" only if test files changed in the diff; tick "does not require tests" only if the change is non-functional (docs, config, tooling, skills).
  - *Documentation*: tick "docs were updated" only if README/docs files changed; tick "does not require updating documentation" only if nothing user-facing changed.
  - *Behavior*: tick "no behavior was changed" only if the diff is limited to non-runtime files (skills, docs, CI config, tests); otherwise tick one of the other two options and explain why.
  - *Security*: tick "no security aspects" only if the Security persona (step 2) genuinely found nothing; otherwise tick the appropriate other option and reference the finding.

If a field genuinely cannot be determined, write a short explicit note (e.g. "No linked issue found in branch/commit history") instead of leaving an angle-bracket placeholder.

The output must follow this structure when pasted into a PR description:

```markdown
<filled summary>

### Desired Outcome

<filled>

### Implemented Changes

- <filled bullets>

### Connected Issue/Story

Resolves #<n>  (omit this line if none found)

CyberArk internal issue ID: <filled or note>

### Definition of Done

#### Changelog
- [ ] The CHANGELOG has been updated, or
- [ ] This PR does not include user-facing changes and doesn't require a CHANGELOG update

#### Test coverage
- [ ] This PR includes new unit and integration tests to go with the code changes, or
- [ ] The changes in this PR do not require tests

#### Documentation
- [ ] Docs (e.g. READMEs) were updated in this PR
- [ ] A follow-up issue to update official docs has been filed here: [insert issue ID]
- [ ] This PR does not require updating any documentation

#### Behavior
- [ ] This PR changes product behavior and has been reviewed by a PO, or
- [ ] These changes are part of a larger initiative that will be reviewed later, or
- [ ] No behavior was changed with this PR

#### Security
- [ ] Security architect has reviewed the changes in this PR,
- [ ] These changes are part of a larger initiative with a separate security review, or
- [ ] There are no security aspects to these changes
```

(the checkboxes above are the template shape — in the actual generated report, exactly one box per subsection must be ticked `[x]`, the rest `[ ]`)

## Usage Instructions

Run this command before every commit that finalizes a task:

```
@ai-pr-review run analysis and generate report
```

## Port.io Metadata

- **Maturity Level**: Tier 2 (Repeatable Skill)
- **Service**: Secrets Manager Integrations
