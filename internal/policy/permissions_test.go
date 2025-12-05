package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestPermissions(t *testing.T) {
	p := Permit{
		Resource:   Variable("foo/bar"),
		Role:       Role{"host", "data/testhost"},
		Privileges: []string{"read", "execute", "update"},
	}
	pt := Permit{
		Resource:   Variable("foo/baz"),
		Role:       Role{"host", "data/testhost"},
		Privileges: []string{"read", "execute", "update"},
	}
	permits := []Permit{p, pt}

	yml, err := yaml.Marshal(permits)
	assert.NoError(t, err)
	assert.Equal(t, `- !permit
  resource: !variable foo/bar
  role: !host /data/testhost
  privileges: [read, execute, update]
- !permit
  resource: !variable foo/baz
  role: !host /data/testhost
  privileges: [read, execute, update]
`, string(yml))
}
