package policy

import "gopkg.in/yaml.v3"

type Permit struct {
	Resource   Variable `yaml:"resource"`
	Role       Host     `yaml:"role"`
	Privileges []string `yaml:"privileges,flow"`
}

type Deny struct {
	Resource   Variable `yaml:"resource"`
	Role       Host     `yaml:"role"`
	Privileges []string `yaml:"privileges,flow"`
}

func (p Permit) MarshalYAML() (interface{}, error) {
	type alias Permit
	node := &yaml.Node{}
	if err := node.Encode(alias(p)); err != nil {
		return nil, err
	}
	node.Tag = "!permit"
	return node, nil
}

func (p *Permit) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type alias Permit
	var a alias
	if err := unmarshal(&a); err != nil {
		return err
	}
	*p = Permit(a)
	return nil
}

func (p Deny) MarshalYAML() (interface{}, error) {
	type alias Deny
	node := &yaml.Node{}
	if err := node.Encode(alias(p)); err != nil {
		return nil, err
	}
	node.Tag = "!deny"
	return node, nil
}

func (p *Deny) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type alias Deny
	var a alias
	if err := unmarshal(&a); err != nil {
		return err
	}
	*p = Deny(a)
	return nil
}

type Variable string

func (v Variable) MarshalYAML() (interface{}, error) {
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!variable",
		Value: string(v),
	}
	return node, nil
}

func (v *Variable) UnmarshalYAML(unmarshal func(interface{}) error) error {
	node := &yaml.Node{}
	if err := unmarshal(node); err != nil {
		return err
	}
	*v = Variable(node.Value)
	return nil
}

type Host string

func (h Host) MarshalYAML() (interface{}, error) {
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!host",
		Value: string(h),
	}
	return node, nil
}

func (h *Host) UnmarshalYAML(unmarshal func(interface{}) error) error {
	node := &yaml.Node{}
	if err := unmarshal(node); err != nil {
		return err
	}
	*h = Host(node.Value)
	return nil
}
