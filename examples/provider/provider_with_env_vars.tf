terraform {
  required_providers {
    conjur = {
      source  = "cyberark/conjur"
    }
  }
}

provider "conjur" {}
