# Contributing

For general contribution and community guidelines, please see the [community repo](https://github.com/cyberark/community).

### Prerequisites

To work on this code, you must have at least Go version 1.12 installed locally
on your system.

### Build binaries:

```
./bin/build
```

### Run integration tests:

#### Conjur 5 OSS

```
./bin/test oss
```

#### Conjur 5 Enterprise
Note that to run the enterprise tests, you'll need to have set up your machine
to access our [internal registry](https://github.com/conjurinc/docs/blob/master/reference/docker_registry.md#docker-registry-v2), and you must be logged in.

```
./bin/test enterprise
```

## Contributing

1. [Fork the project](https://help.github.com/en/github/getting-started-with-github/fork-a-repo)
2. [Clone your fork](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository)
3. Make local changes to your fork by editing files
3. [Commit your changes](https://help.github.com/en/github/managing-files-in-a-repository/adding-a-file-to-a-repository-using-the-command-line)
4. [Push your local changes to the remote server](https://help.github.com/en/github/using-git/pushing-commits-to-a-remote-repository)
5. [Create new Pull Request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request-from-a-fork)

From here your pull request will be reviewed and once you've responded to all
feedback it will be merged into the project. Congratulations, you're a
contributor!

## Releasing

The following checklist should be followed when creating a release:

- [ ] Follow the [Conjur release proceedure](https://github.com/cyberark/community/blob/main/Conjur/CONTRIBUTING.md#release-process)

- [ ] Update homebrew tools
  - [ ] In [`cyberark/homebrew-tools`](https://github.com/cyberark/homebrew-tools) repo, update
        the [`terraform-provider-conjur.rb` formula](https://github.com/cyberark/homebrew-tools/blob/main/terraform-provider-conjur.rb)
        using the file `dist/terraform-provider-conjur.rb` from the artifacts Jenkins built.

- [ ] Public to Terraform Registry
  - [ ] Request infra sign the SHA256SUMS file for the release and attach the resulting .sig file to the github release