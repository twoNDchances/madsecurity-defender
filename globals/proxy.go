package globals

import (
	"madsecurity-defender/utils"
	"net"
	"strings"
)

type Proxy struct {
	TLS    bool
	Host   string
	Port   uint32
	Prefix string
	Health string
	Sync   string
	Apply  string
	Revoke string
}

func (p *Proxy) Validate() ListError {
	errors := make(ListError, 0)
	if err := p.validateHost(); err != nil {
		errors = append(errors, err)
	}
	if err := p.validatePort(); err != nil {
		errors = append(errors, err)
	}
	if err := p.validatePath(); err != nil {
		errors = append(errors, err)
	}
	if len(errors) > 0 {
		return errors
	}
	return nil
}

func (p *Proxy) validateHost() error {
	if p.Host == "" {
		return nil
	}
	if p.Host == "0.0.0.0" {
		return nil
	}
	if net.ParseIP(p.Host) == nil {
		return utils.NewProxyError("Host", "Invalid IP")
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return utils.NewProxyError("Host", err.Error())
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.To4() == nil {
			continue
		}
		if ipNet.IP.String() == p.Host {
			return nil
		}
	}
	return utils.NewProxyError("Host", "Invalid host")
}

func (p *Proxy) validatePort() error {
	if p.Port <= 0 || p.Port >= ^uint32(0) {
		return utils.NewProxyError("Port", "Must in range 1 -> 4294967295")
	}
	return nil
}

func (p *Proxy) validatePath() error {
	paths := DictString{
		"Prefix": p.Prefix,
		"Health": p.Health,
		"Sync":   p.Sync,
		"Apply":  p.Apply,
		"Revoke": p.Revoke,
	}
	for name, path := range paths {
		if name == "Prefix" && len(path) == 0 {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			return utils.NewProxyError(name, "Must start with ")
		}
	}
	return nil
}
