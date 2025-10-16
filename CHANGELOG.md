# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.8.0] - 2025-10-16
### Changed
- Updated documentation to align with Conjur Enterprise name change to Secrets Manager. (CNJR-10995)
### Added
- Support for Conjur permissions via the conjur_permission resource
- Support for Conjur V2 Workloads API via the conjur_host resource
- Support for Conjur V2 Authenticators API via the conjur_authenticator resource
- Support for Conjur Groups via the conjur_group resource

## [0.7.1] - 2025-07-01
### Fixed
- Configuration via environment variables

## [0.7.0] - 2025-06-09
### Added
- Support AWS, Azure, GCP and JWT Token Authentication
- Telemetry changes

## [0.6.11] - 2025-04-04
### Added
- Add the test cases and integrate Codacy

## [0.6.10] - 2025-03-21
### Changed
- Upgrade Go to 1.24.x

## [0.6.9] - 2024-10-22
### Changed
- Update conjur-api-go to v0.12.4
  [cyberark/terraform-provider-conjur#137](https://github.com/cyberark/terraform-provider-conjur/pull/137)

## [0.6.8] - 2024-08-01
### Changed
- Update to support new automated release process and correct terraform registry
  publication.

## [0.6.7] - 2024-04-08

### Changed
- Upgrade Go to 1.22 (CONJSE-1842)

## [0.6.6] - 2023-06-21
### Security
- Updated golang.org/x/sys to v0.8.0 and golang.org/x/text to v0.9.0
  [cyberark/terraform-provider-conjur#123](https://github.com/cyberark/terraform-provider-conjur/pull/123)
- Updated golang.org/x/net to v0.7.0 for CVE-2022-41721 and CVE-2022-41723, and
  golang.org/x/text to v0.3.8 for CVE_2022-32149
  [cyberark/terraform-provider-conjur#117](https://github.com/cyberark/terraform-provider-conjur/pull/117)

## [0.6.5] - 2022-11-30
### Changed
- Added support for Conjur Cloud by appending `appliance_url` with `/api` [cyberark/terraform-provider-conjur#115](https://github.com/cyberark/terraform-provider-conjur/pull/115)

## [0.6.4] - 2022-11-14
### Security
- Added replaces for 2 versions of golang.org/x/crypto brought in by the terraform sdk to resolve CVE-2021-43565
  [cyberark/terraform-provider-conjur#111](https://github.com/cyberark/terraform-provider-conjur/pull/111)
- Upgraded to Go 1.19 [cyberark/terraform-provider-conjur#110](https://github.com/cyberark/terraform-provider-conjur/pull/110)
- Forced golang.org/x/net to use v0.0.0-20220923203811-8be639271d50 to resolve CVE-2022-27664
  [cyberark/terraform-provider-conjur#109](https://github.com/cyberark/terraform-provider-conjur/pull/109)

## [0.6.3] - 2022-08-17
### Changed
- Updated Terraform Plugin SDK to v2. This removes support for Terraform 0.11.
  [cyberark/terraform-provider-conjur#106](https://github.com/cyberark/terraform-provider-conjur/pull/106)
- Updated direct dependencies (conjur-api-go -> 0.10.1 and github.com/hashicorp/terraform-plugin-sdk -> 1.17.2)
  [cyberark/terraform-provider-conjur#102](https://github.com/cyberark/terraform-provider-conjur/pull/102)

### Security
- Add replace statements to go.mod to remove 3rd party dependencies with known vulnerabilities from our 
  dependency tree. [cyberark/terraform-provider-conjur#103](https://github.com/cyberark/terraform-provider-conjur/pull/103)
  [cyberark/terraform-provider-conjur#104](https://github.com/cyberark/terraform-provider-conjur/pull/104)
  [cyberark/terraform-provider-conjur#105](https://github.com/cyberark/terraform-provider-conjur/pull/105)
  [cyberark/terraform-provider-conjur#107](https://github.com/cyberark/terraform-provider-conjur/pull/107)

## [0.6.2] - 2021-09-02
### Added
- Documentation layout for the [Terraform Registry](https://registry.terraform.io)

## [0.6.1] - 2021-09-02
### Changed
- Archive format changed to support publishing to registry.terraform.io

## [0.6.0] - 2021-08-12
### Added
- Build for Apple M1 silicon.
  [cyberark/terraform-provider-conjur#84](https://github.com/cyberark/terraform-provider-conjur/issues/84)

## [0.5.0] - 2021-05-06
### Added
- Validated support with Terraform v0.15. Please note that in v0.15, behavior
  around [sensitive output values](https://www.terraform.io/upgrade-guides/0-15.html#sensitive-output-values)
  changed; with Terraform v0.15, you **must** mark output values with
  "sensitive: true" if its definition includes any Conjur-provided secret values.
  [cyberark/terraform-provider-conjur#76](https://github.com/cyberark/terraform-provider-conjur/issues/76)

### Changed
- Plugin now uses the [Terraform Plugin SDK](https://github.com/hashicorp/terraform-plugin-sdk)
  instead of Terraform core as its plugin library. With this change, the Go
  version was also incremented to 1.15.
  [cyberark/terraform-provider-conjur#76](https://github.com/cyberark/terraform-provider-conjur/issues/76)

## [0.4.0] - 2020-04-29
### Added
- You can now specify `account`, `appliance_url`, `ssl_cert`, and `ssl_cert_path` values
  directly in the `.tf` provider config [#29](https://github.com/cyberark/terraform-provider-conjur/issues/29)

## [0.3.1] - 2020-04-20
### Fixed
- Each brew recipe binary now includes the provider version [#47](https://github.com/cyberark/terraform-provider-conjur/issues/47)
- Updated output binary file names to include version suffix so that the
  version command returns the correct version [#30](https://github.com/cyberark/terraform-provider-conjur/issues/30)

## [0.3.0] - 2020-04-13
### Changed
- Converted to Go modules
- Updated build to use official Goreleaser image
- Code now builds against Terraform v0.12

## [0.2.0] - 2018-08-31
### Added
- Homebrew installer, see https://github.com/cyberark/terraform-provider-conjur#homebrew-macos for instructions.

## 0.1.0 - 2018-08-28
### Added
- Initial release
- Use https://github.com/cyberark/conjur-api-go to read configuration.

[Unreleased]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.9...HEAD
[0.8.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.11...v0.7.0
[0.6.11]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.10...v0.6.11
[0.6.10]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.9...v0.6.10
[0.6.9]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.8...v0.6.9
[0.6.8]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.7...v0.6.8
[0.6.7]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.6...v0.6.7
[0.6.6]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.5...v0.6.6
[0.6.5]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.1.0...v0.2.0
