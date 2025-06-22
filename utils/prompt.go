package utils

import (
	"fmt"
)

type Color string

const (
	reset  Color = "\033[0m"
	RED    Color = "\033[31m"
	YELLOW Color = "\033[33m"
	GREEN  Color = "\033[32m"
	BLUE   Color = "\033[34m"
)

type Promopt struct {
	Module string
	Field  string
	Kind   string
	Msg    string
	Color  Color
}

func (p *Promopt) Error() error {
	if p.Color == "" {
		return fmt.Errorf("[%s][%s][%s]: %s", p.Module, p.Field, p.Kind, p.Msg)
	}
	return fmt.Errorf("%s[%s][%s][%s]: %s%s", p.Color, p.Module, p.Field, p.Kind, p.Msg, reset)
}

func NewProxyError(field, msg string) error {
	promopt := Promopt{
		Module: "Proxy",
		Field:  field,
		Kind:   "Error",
		Msg:    msg,
		Color:  RED,
	}
	return promopt.Error()
}
