To regenerate certificates, use [this](https://github.com/conjurdemos/dap-intro/tree/master/tools/simple-certificates)
tool:
```sh-session
$ ./generate_certificates 1 conjur-server
```

Copy the following:
- `certificates/ca-chain.cert.pem` -> `ca.crt`
- `certificates/nodes/conjur-server.mycompany.local/conjur-server.mycompany.local.cert.pem` -> `conjur.crt`
- `certificates/nodes/conjur-server.mycompany.local/conjur-server.mycompany.local.key.pem` -> `conjur.key`
