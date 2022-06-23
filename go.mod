module github.com/cyberark/terraform-provider-conjur

require (
	github.com/cyberark/conjur-api-go v0.10.1
	github.com/hashicorp/terraform-plugin-sdk v1.17.2
)

require (
	cloud.google.com/go v0.65.0 // indirect
	cloud.google.com/go/storage v1.10.0 // indirect
	github.com/Masterminds/goutils v1.1.0 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible // indirect
	github.com/agext/levenshtein v1.2.2 // indirect
	github.com/apparentlymart/go-cidr v1.1.0 // indirect
	github.com/apparentlymart/go-textseg/v12 v12.0.0 // indirect
	github.com/apparentlymart/go-textseg/v13 v13.0.0 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/aws/aws-sdk-go v1.37.0 // indirect
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d // indirect
	github.com/bgentry/speakeasy v0.1.0 // indirect
	github.com/fatih/color v1.7.0 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/google/uuid v1.1.2 // indirect
	github.com/googleapis/gax-go/v2 v2.0.5 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-getter v1.5.3 // indirect
	github.com/hashicorp/go-hclog v0.9.2 // indirect
	github.com/hashicorp/go-multierror v1.0.0 // indirect
	github.com/hashicorp/go-plugin v1.3.0 // indirect
	github.com/hashicorp/go-safetemp v1.0.0 // indirect
	github.com/hashicorp/go-uuid v1.0.1 // indirect
	github.com/hashicorp/go-version v1.3.0 // indirect
	github.com/hashicorp/hcl/v2 v2.8.2 // indirect
	github.com/hashicorp/terraform-svchost v0.0.0-20200729002733-f050f53b9734 // indirect
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jstemmer/go-junit-report v0.9.1 // indirect
	github.com/klauspost/compress v1.11.2 // indirect
	github.com/mattn/go-colorable v0.1.1 // indirect
	github.com/mattn/go-isatty v0.0.5 // indirect
	github.com/mitchellh/cli v1.1.2 // indirect
	github.com/mitchellh/copystructure v1.0.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-testing-interface v1.0.4 // indirect
	github.com/mitchellh/go-wordwrap v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/oklog/run v1.0.0 // indirect
	github.com/posener/complete v1.2.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spf13/afero v1.2.2 // indirect
	github.com/ulikunitz/xz v0.5.8 // indirect
	github.com/vmihailenco/msgpack/v4 v4.3.12 // indirect
	github.com/vmihailenco/tagparser v0.1.1 // indirect
	github.com/zclconf/go-cty v1.8.2 // indirect
	github.com/zclconf/go-cty-yaml v1.0.2 // indirect
	go.opencensus.io v0.22.4 // indirect
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2 // indirect
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	golang.org/x/mod v0.3.0 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43 // indirect
	golang.org/x/sys v0.0.0-20220517195934-5e4e11fc645e // indirect
	golang.org/x/text v0.3.6 // indirect
	golang.org/x/tools v0.0.0-20201028111035-eafbe7b904eb // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/api v0.34.0 // indirect
	google.golang.org/appengine v1.6.6 // indirect
	google.golang.org/genproto v0.0.0-20200904004341-0bd0a958aa1d // indirect
	google.golang.org/grpc v1.32.0 // indirect
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

go 1.17

// Security fixes to ensure we don't have old vulnerable packages in our
// dependency tree. We're often not vulnerable, but removing them to ensure
// we never end up selecting them when other dependencies change.

// Only put specific versions on the left side of the =>
// so we don't downgrade future versions unintentionally.

replace github.com/aws/aws-sdk-go v1.15.78 => github.com/aws/aws-sdk-go v1.34.2

replace github.com/hashicorp/go-getter v1.5.3 => github.com/hashicorp/go-getter v1.6.1

replace github.com/Masterminds/goutils v1.1.0 => github.com/Masterminds/goutils v1.1.1

replace golang.org/x/crypto v0.0.0-20190219172222-a4c6cb3142f2 => golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b

replace golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2 => golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b

replace golang.org/x/crypto v0.0.0-20190426145343-a29dc8fdc734 => golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b

replace golang.org/x/crypto v0.0.0-20190510104115-cbcb75029529 => golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b

replace golang.org/x/crypto v0.0.0-20190605123033-f99c8df09eb5 => golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b

replace golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550 => golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b

replace golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 => golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b

replace golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a => golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b

replace golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2 => golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b

replace golang.org/x/net v0.0.0-20180530234432-1e491301e022 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20180724234803-3673e40ba225 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20180811021610-c39426892332 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20180826012351-8a410e7b638d => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20190108225652-1e06a53dbb7e => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20190213061140-3a22650c66bd => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20190311183353-d8887717615a => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20190501004415-9ce7a6920f09 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20190503192946-f4e77d36d62c => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20190603091049-60506f45cf65 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20190620200207-3b0461eec859 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20190628185345-da137c7871d7 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20190724013045-ca1201d0de80 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20191009170851-d66e71096ffb => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200114155413-6afb5195e5aa => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200202094626-16171245cfb2 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200222125558-5a598a2470a0 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200226121028-0de0cce0169b => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200301022130-244492dfa37a => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200501053045-e0ff5e5a1de5 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200506145744-7e3656a0809f => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200513185701-a91f0712d120 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200520182314-0ba52f642ac2 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200625001655-4c5254603344 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200707034311-ab3426394381 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20200822124328-c89045814202 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20201021035429-f5854403a974 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20201110031124-69a78807bb2b => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20210326060303-6b1517762897 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 => golang.org/x/net v0.0.0-20211209124913-491a49abca63

replace golang.org/x/text v0.0.0-20170915032832-14c0d48ead0c => golang.org/x/text v0.3.7

replace golang.org/x/text v0.3.0 => golang.org/x/text v0.3.7

replace golang.org/x/text v0.3.1-0.20180807135948-17ff2d5776d2 => golang.org/x/text v0.3.7

replace golang.org/x/text v0.3.2 => golang.org/x/text v0.3.7

replace golang.org/x/text v0.3.3 => golang.org/x/text v0.3.7

replace golang.org/x/text v0.3.5 => golang.org/x/text v0.3.7

replace golang.org/x/text v0.3.6 => golang.org/x/text v0.3.7

replace gopkg.in/yaml.v2 v2.2.2 => gopkg.in/yaml.v2 v2.2.8

replace gopkg.in/yaml.v2 v2.2.4 => gopkg.in/yaml.v2 v2.2.8
