# Conjur Secret Data Source

This Data Source retrieves a secret from Conjur which can then be utilized by Terraform

## Example Usage

```hcl
    data "conjur_secret" "dbpass" {
        name = "my/shiny/dbpass"
    }

    output "dbpass_output" {
    value = "${data.conjur_secret.dbpass.value}"
    
    # Must mark this output value as sensitive for Terraform v0.15+,
    # because it's derived from a Conjur variable value that is declared
    # as sensitive.
    sensitive = true
    }
```
Secrets like `data.conjur_secret.dbpass.value` can be used in any Terraform resources.

View an example Terraform manifest and Conjur policies in the
[test/](test/) directory in this project.
