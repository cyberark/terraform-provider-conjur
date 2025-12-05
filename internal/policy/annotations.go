package policy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type Annotations struct {
	VariableID  string            `yaml:"id"`
	Annotations map[string]string `yaml:"annotations"`
}

func (v Annotations) MarshalYAML() (interface{}, error) {
	// Ensure empty map is encoded as `{}` rather than null
	if v.Annotations == nil {
		v.Annotations = map[string]string{}
	}

	// Wrap the struct inside a YAML node with tag !variable
	node := &yaml.Node{}
	if err := node.Encode(struct {
		ID          string            `yaml:"id"`
		Annotations map[string]string `yaml:"annotations"`
	}{
		ID:          v.VariableID,
		Annotations: v.Annotations,
	}); err != nil {
		return nil, err
	}

	node.Tag = "!variable"
	return node, nil
}

func (v *Annotations) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var node yaml.Node
	if err := unmarshal(&node); err != nil {
		return err
	}

	if node.Tag != "!variable" {
		return fmt.Errorf("expected !variable tag, got %s", node.Tag)
	}

	// Decode into the struct
	aux := struct {
		ID          string            `yaml:"id"`
		Annotations map[string]string `yaml:"annotations"`
	}{}

	if err := node.Decode(&aux); err != nil {
		return err
	}

	v.VariableID = aux.ID
	if aux.Annotations == nil {
		v.Annotations = map[string]string{}
	} else {
		v.Annotations = aux.Annotations
	}

	return nil
}
