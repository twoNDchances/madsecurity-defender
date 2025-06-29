package globals

import (
	"madsecurity-defender/utils"
	"net"
	"slices"
	"strings"
)

type TLS struct {
	Enable bool
	Key    string
	Crt    string
}

type Entry struct {
	TLS  TLS
	Host string
	Port int
}

var methods = ListString{
	"post",
	"put",
	"patch",
	"delete",
}

type Server struct {
	Entry        Entry
	Prefix       string
	Health       string
	HealthMethod string
	Sync         string
	SyncMethod   string
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

func (s *Server) validateKeyAndCrt() error {
	if s.Entry.TLS.Enable {
		keyInfo, err := utils.CheckFileExists(s.Entry.TLS.Key)
		if err != nil {
			return utils.NewServerError("Key", err.Error())
		}
		if keyInfo.IsDir() {
			return utils.NewServerError("Key", "This path is directory, .key file is required")
		}
		if utils.GetExtension(s.Entry.TLS.Key) != ".key" {
			return utils.NewServerError("Key", "Extension is not a .key")
		}

		crtInfo, err := utils.CheckFileExists(s.Entry.TLS.Crt)
		if err != nil {
			return utils.NewServerError("Crt", err.Error())
		}
		if crtInfo.IsDir() {
			return utils.NewServerError("Crt", "This path is directory, .crt file is required")
		}
		if utils.GetExtension(s.Entry.TLS.Crt) != ".crt" {
			return utils.NewServerError("Crt", "Extension is not a .crt")
		}
	}
	return nil
}

func (s *Server) validateHost() error {
	if s.Entry.Host == "" {
		return nil
	}
	if s.Entry.Host == "0.0.0.0" {
		return nil
	}
	if net.ParseIP(s.Entry.Host) == nil {
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
		if ipNet.IP.String() == s.Entry.Host {
			return nil
		}
	}
	return utils.NewServerError("Host", "Invalid host")
}

func (s *Server) validatePort() error {
	if s.Entry.Port <= 0 || s.Entry.Port >= 100000 {
		return utils.NewServerError("Port", "Must in range 1 -> 99999")
	}
	return nil
}

func (s *Server) validatePath() error {
	paths := DictString{
		"Prefix": s.Prefix,
		"Health": s.Health,
		"Sync":   s.Sync,
		"Apply":  s.Apply,
		"Revoke": s.Revoke,
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

func (s *Server) validateMethod(route string) error {
	errorMsg := "Only support 'post', 'put', 'patch' or 'delete'"
	if route == "health" {
		if !slices.Contains(methods, strings.ToLower(s.HealthMethod)) {
			return utils.NewServerError("Health.Method", errorMsg)
		}
	}
	if route == "sync" {
		if !slices.Contains(methods, strings.ToLower(s.SyncMethod)) {
			return utils.NewServerError("Sync.Method", errorMsg)
		}
	}
	if route == "apply" {
		if !slices.Contains(methods, strings.ToLower(s.ApplyMethod)) {
			return utils.NewServerError("Apply.Method", errorMsg)
		}
	}
	if route == "revoke" {
		if !slices.Contains(methods, strings.ToLower(s.RevokeMethod)) {
			return utils.NewServerError("Apply.Method", errorMsg)
		}
	}
	return nil
}

func (s *Server) GetEntry() Entry {
	return s.Entry
}
