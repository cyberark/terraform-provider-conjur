package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestAnnotations(t *testing.T) {
	ann := Annotations{
		VariableID: "foo",
		Annotations: map[string]string{
			"foo": "bar",
			"bar": "baz",
			"baz": "",
		},
	}

	yml, err := yaml.Marshal([]Annotations{ann})
	assert.NoError(t, err)
	assert.Equal(t, `- !variable
  id: foo
  annotations:
    bar: baz
    baz: ""
    foo: bar
`, string(yml))
}
