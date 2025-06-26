package globals

import (
	"madsecurity-defender/utils"
	"net"
)

type Proxy struct {
	TlsEnable bool
	TlsKey    string
	TlsCrt    string
	Host      string
	Port      uint32
}

func (p *Proxy) Validate() ListError {
	if errors := Validate(
		p.validateKeyAndCrt(),
		p.validateHost(),
		p.validatePort(),
	); len(errors) > 0 {
		return errors
	}
	return nil
}

func (p *Proxy) validateKeyAndCrt() error {
	if p.TlsEnable {
		keyInfo, err := utils.CheckFileExists(p.TlsKey)
		if err != nil {
			return utils.NewProxyError("Key", err.Error())
		}
		if keyInfo.IsDir() {
			return utils.NewProxyError("Key", "This path is directory, .key file is required")
		}
		if utils.GetExtension(p.TlsKey) != ".key" {
			return utils.NewProxyError("Key", "Extension is not a .key")
		}

		crtInfo, err := utils.CheckFileExists(p.TlsCrt)
		if err != nil {
			return utils.NewProxyError("Crt", err.Error())
		}
		if crtInfo.IsDir() {
			return utils.NewProxyError("Crt", "This path is directory, .crt file is required")
		}
		if utils.GetExtension(p.TlsCrt) != ".crt" {
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
