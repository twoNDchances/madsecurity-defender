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

type Server struct {
	TlsEnable    bool
	TlsKey       string
	TlsCrt       string
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

func (p *Server) Validate() ListError {
	if errors := Validate(
		p.validateKeyAndCrt(),
		p.validateHost(),
		p.validatePort(),
		p.validatePath(),
		p.validateMethod("apply"),
		p.validateMethod("revoke"),
	); len(errors) > 0 {
		return errors
	}
	return nil
}

func (p *Server) validateKeyAndCrt() error {
	if p.TlsEnable {
		keyInfo, err := utils.CheckFileExists(p.TlsKey)
		if err != nil {
			return utils.NewServerError("Key", err.Error())
		}
		if keyInfo.IsDir() {
			return utils.NewServerError("Key", "This path is directory, .key file is required")
		}
		if utils.GetExtension(p.TlsKey) != ".key" {
			return utils.NewServerError("Key", "Extension is not a .key")
		}

		crtInfo, err := utils.CheckFileExists(p.TlsCrt)
		if err != nil {
			return utils.NewServerError("Crt", err.Error())
		}
		if crtInfo.IsDir() {
			return utils.NewServerError("Crt", "This path is directory, .crt file is required")
		}
		if utils.GetExtension(p.TlsCrt) != ".crt" {
			return utils.NewServerError("Crt", "Extension is not a .crt")
		}
	}
	return nil
}

func (p *Server) validateHost() error {
	if p.Host == "" {
		return nil
	}
	if p.Host == "0.0.0.0" {
		return nil
	}
	if net.ParseIP(p.Host) == nil {
		return utils.NewServerError("Host", "Invalid IP")
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return utils.NewServerError("Host", err.Error())
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
	return utils.NewServerError("Host", "Invalid host")
}

func (p *Server) validatePort() error {
	if p.Port <= 0 || p.Port >= ^uint32(0) {
		return utils.NewServerError("Port", "Must in range 1 -> 4294967295")
	}
	return nil
}

func (p *Server) validatePath() error {
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
			return utils.NewServerError(name, "Must start with /")
		}
	}
	return nil
}

func (p *Server) validateMethod(route string) error {
	errorMsg := "Only support 'post', 'put', 'patch' or 'delete'"
	if route == "apply" {
		if !slices.Contains(methods, strings.ToLower(p.ApplyMethod)) {
			return utils.NewServerError("Apply.Method", errorMsg)
		}
	}
	if route == "revoke" {
		if !slices.Contains(methods, strings.ToLower(p.RevokeMethod)) {
			return utils.NewServerError("Apply.Method", errorMsg)
		}
	}
	return nil
}
