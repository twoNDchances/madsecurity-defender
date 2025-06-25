package globals

import (
	"madsecurity-defender/utils"
	"net"
	"slices"
	"strings"
)

var methods = ListString{
	"post",
	"put",
	"patch",
	"delete",
}

type Proxy struct {
	TLS          bool
	Key          string
	Crt          string
	Host         string
	Port         uint32
	Prefix       string
	Health       string
	Sync         string
	Apply        string
	ApplyMethod  string
	Revoke       string
	RevokeMethod string
}

func (p *Proxy) Validate() ListError {
	errors := make(ListError, 0)
	if err := p.validateKeyAndCrt(); err != nil {
		errors = append(errors, err)
	}
	if err := p.validateHost(); err != nil {
		errors = append(errors, err)
	}
	if err := p.validatePort(); err != nil {
		errors = append(errors, err)
	}
	if err := p.validatePath(); err != nil {
		errors = append(errors, err)
	}
	if err := p.validateMethod("apply"); err != nil {
		errors = append(errors, err)
	}
	if err := p.validateMethod("revoke"); err != nil {
		errors = append(errors, err)
	}
	if len(errors) > 0 {
		return errors
	}
	return nil
}

func (p *Proxy) validateKeyAndCrt() error {
	if p.TLS {
		keyInfo, err := utils.CheckFileExists(p.Key)
		if err != nil {
			return utils.NewProxyError("Key", err.Error())
		}
		if keyInfo.IsDir() {
			return utils.NewProxyError("Key", "This path is directory, .key file is required")
		}
		if utils.GetExtension(p.Key) != ".key" {
			return utils.NewProxyError("Key", "Extension is not a .key")
		}

		crtInfo, err := utils.CheckFileExists(p.Crt)
		if err != nil {
			return utils.NewProxyError("Crt", err.Error())
		}
		if crtInfo.IsDir() {
			return utils.NewProxyError("Crt", "This path is directory, .crt file is required")
		}
		if utils.GetExtension(p.Crt) != ".crt" {
			return utils.NewProxyError("Crt", "Extension is not a .crt")
		}
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

func (p *Proxy) validateMethod(route string) error {
	errorMsg := "Only support 'post', 'put', 'patch' or 'delete'"
	if route == "apply" {
		if !slices.Contains(methods, strings.ToLower(p.ApplyMethod)) {
			return utils.NewProxyError("Apply.Method", errorMsg);
		}
	}
	if route == "revoke" {
		if !slices.Contains(methods, strings.ToLower(p.RevokeMethod)) {
			return utils.NewProxyError("Apply.Method", errorMsg);
		}
	}
	return nil
}
