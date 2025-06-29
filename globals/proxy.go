package globals

import (
	"madsecurity-defender/utils"
	"net"
)

type Proxy struct {
	Entry Entry
	ViolationScore int
	ViolationLevel int
}

func (p *Proxy) Validate() ListError {
	if errors := Validate(
		p.validateKeyAndCrt(),
		p.validateHost(),
		p.validatePort(),
		p.validateViolationScore(),
		p.validateViolationLevel(),
	); len(errors) > 0 {
		return errors
	}
	return nil
}

func (p *Proxy) validateKeyAndCrt() error {
	if p.Entry.TLS.Enable {
		keyInfo, err := utils.CheckFileExists(p.Entry.TLS.Key)
		if err != nil {
			return utils.NewProxyError("Key", err.Error())
		}
		if keyInfo.IsDir() {
			return utils.NewProxyError("Key", "This path is directory, .key file is required")
		}
		if utils.GetExtension(p.Entry.TLS.Key) != ".key" {
			return utils.NewProxyError("Key", "Extension is not a .key")
		}

		crtInfo, err := utils.CheckFileExists(p.Entry.TLS.Crt)
		if err != nil {
			return utils.NewProxyError("Crt", err.Error())
		}
		if crtInfo.IsDir() {
			return utils.NewProxyError("Crt", "This path is directory, .crt file is required")
		}
		if utils.GetExtension(p.Entry.TLS.Crt) != ".crt" {
			return utils.NewProxyError("Crt", "Extension is not a .crt")
		}
	}
	return nil
}

func (p *Proxy) validateHost() error {
	if p.Entry.Host == "" {
		return nil
	}
	if p.Entry.Host == "0.0.0.0" {
		return nil
	}
	if net.ParseIP(p.Entry.Host) == nil {
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
		if ipNet.IP.String() == p.Entry.Host {
			return nil
		}
	}
	return utils.NewProxyError("Host", "Invalid host")
}

func (p *Proxy) validatePort() error {
	if p.Entry.Port <= 0 || p.Entry.Port >= 100000 {
		return utils.NewProxyError("Port", "Must in range 1 -> 99999")
	}
	return nil
}

func (p *Proxy) GetEntry() Entry {
	return p.Entry
}

func (p *Proxy) validateViolationScore() error {
	if p.ViolationScore > 999999999 {
		return utils.NewProxyError("Violation.Score", "999999999 is the highest limit")
	}
	return nil
}

func (p *Proxy) validateViolationLevel() error {
	if p.ViolationLevel > 999999999 {
		return utils.NewProxyError("Violation.Level", "999999999 is the highest limit")
	}
	return nil
}
