# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cyberark/terraform-provider-conjur/compare/v0.1.0...v0.2.0
