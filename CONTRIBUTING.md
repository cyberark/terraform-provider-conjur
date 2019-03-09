## Development

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
