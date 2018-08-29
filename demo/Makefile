dir := $(shell printf "%s_%s" $(shell go env GOHOSTOS GOHOSTARCH))
terraform.d/plugins/$(dir)/terraform-provider-conjur: $(shell go env GOPATH)/bin/terraform-provider-conjur
	mkdir -p $(@D)
	cp $< $@
