# Contributing

For general contribution and community guidelines, please see the [community repo](https://github.com/cyberark/community).

### Prerequisites

To work on this code, you must have at least Go version 1.24 installed locally
on your system.

### Build binaries:

```sh
./bin/build
```

### Run integration tests:

#### Conjur OSS

```sh
./bin/test --target oss --test-case <test_case>
```
Where `<test_case>` is one of:
- api-key
- jwt
- iam 
- azure
- gcp


#### Conjur Enterprise
Note that to run the enterprise tests, you'll need to have set up your machine
to access our [internal registry](https://github.com/conjurinc/docs/blob/master/reference/docker_registry.md#docker-registry-v2), and you must be logged in.

```sh
./bin/test --target enterprise --test-case <test_case>
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

### Verify and update dependencies

1.  Review the changes to `go.mod` since the last release and make any needed
    updates to [NOTICES.txt](./NOTICES.txt):
    *   Verify that dependencies fit into supported licenses types:
        ```shell
         go-licenses check ./... --allowed_licenses="MIT,ISC,Apache-2.0,BSD-3-Clause,MPL-2.0,BSD-2-Clause" \
            --ignore github.com/cyberark/terraform-provider-conjur \
            --ignore $(go list std | awk 'NR > 1 { printf(",") } { printf("%s",$0) } END { print "" }')
        ```
        If there is new dependency having unsupported license, such license should be included to [notices.tpl](./notices.tpl)
        file in order to get generated in NOTICES.txt.  

        NOTE: The second ignore flag tells the command to ignore standard library packages, which
        may or may not be necessary depending on your local Go installation and toolchain.

    *   If no errors occur, proceed to generate updated NOTICES.txt:
        ```shell
         go-licenses report ./... --template notices.tpl > NOTICES.txt \
            --ignore github.com/cyberark/terraform-provider-conjur \
            --ignore $(go list std | awk 'NR > 1 { printf(",") } { printf("%s",$0) } END { print "" }')
         ```

### Release and Promote

1. Merging into the master branch will automatically trigger a release.
   If successful, this release can be promoted at a later time.
1. Jenkins build parameters can be utilized to promote a successful release
   or manually trigger aditional releases as needed.
1. Reference the [internal automated release doc](https://github.com/conjurinc/docs/blob/master/reference/infrastructure/automated_releases.md#release-and-promotion-process) for releasing and promoting.
1. **After promotion:**
    - **Publish to the Terraform Registry**
    - **Request infra sign the SHA256SUMS file for the release and attach the resulting .sig file to the github release**
