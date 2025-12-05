package policy

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type Role struct {
	Kind    string
	Subject string
}

type Permit struct {
	Resource   Variable `yaml:"resource"`
	Role       Role     `yaml:"role"`
	Privileges []string `yaml:"privileges,flow"`
}

type Deny struct {
	Resource   Variable `yaml:"resource"`
	Role       Role     `yaml:"role"`
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

func (r Role) MarshalYAML() (interface{}, error) {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!" + r.Kind,
		Value: "/" + r.Subject,
	}, nil
}

func (r *Role) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var node yaml.Node
	if err := unmarshal(&node); err != nil {
		return err
	}

	if node.Tag == "" || node.Tag[0] != '!' {
		return fmt.Errorf("invalid role tag %q", node.Tag)
	}

	r.Kind = strings.TrimPrefix(node.Tag, "!")
	r.Subject = strings.TrimPrefix(node.Value, "/")

	return nil
}
