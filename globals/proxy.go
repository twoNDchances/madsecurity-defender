package globals

import (
	"fmt"
	"madsecurity-defender/utils"
	"net"
)

type Proxy struct {
	Entry              Entry
	ViolationScore     int
	ViolationLevel     int
	Severity           Severity
	HistoryAuditPath   string
	HistoryErrorEnable bool
	HistoryErrorPath   string
	Report             Report
}

func (p *Proxy) Validate() ListError {
	if errors := Validate(
		p.validateKeyAndCrt(),
		p.validateHost(),
		p.validatePort(),
		p.validateViolationScore(),
		p.validateViolationLevel(),
		p.validateAuditPath(),
		p.validateErrorPath(),
	); len(errors) > 0 {
		return errors
	}
	if errors := p.Severity.validate(); len(errors) > 0 {
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
	if p.ViolationLevel < 1 || p.ViolationLevel > 999999999 {
		return utils.NewProxyError("Violation.Level", "Must in range 1 -> 999999999")
	}
	return nil
}

func (p *Proxy) validateAuditPath() error {
	return utils.CheckAndCreateDefaultFile(fmt.Sprintf("%s.json", p.HistoryAuditPath), "History.Audit.Path")
}

func (p *Proxy) validateErrorPath() error {
	if !p.HistoryErrorEnable {
		return nil
	}
	return utils.CheckAndCreateDefaultFile(fmt.Sprintf("%s.log", p.HistoryErrorPath), "History.Error.Path")
}

type Severity struct {
	NOTICE   int
	WARNING  int
	ERROR    int
	CRITICAL int
}

func (s *Severity) validate() ListError {
	if errors := Validate(
		s.validateSeverity("Notice"),
		s.validateSeverity("Warning"),
		s.validateSeverity("Error"),
		s.validateSeverity("Critical"),
	); len(errors) > 0 {
		return errors
	}
	return nil
}

func (s *Severity) validateSeverity(name string) error {
	severities := map[string]int{
		"Notice":   s.NOTICE,
		"Warning":  s.WARNING,
		"Error":    s.ERROR,
		"Critical": s.CRITICAL,
	}
	if value := severities[name]; value <= 0 || value >= 100000 {
		return utils.NewProxyError(fmt.Sprintf("Severity.%s", name), "Must in range 1 -> 99999")
	}
	return nil
}

type Report struct {
	ApiPath      string
	ApiHeader    string
	ApiToken     string
	AuthUsername string
	AuthPassword string
}

func (r *Report) Validate() ListError {
	if errors := Validate(
		r.validatePath(),
		r.validateHeader(),
		r.validateToken(),
		r.validateUsername(),
		r.validatePassword(),
	); len(errors) > 0 {
		return errors
	}
	return nil
}

func (r *Report) validatePath() error {
	if len(r.ApiPath) == 0 {
		return utils.NewProxyError("Report.Api.Path", "Empty API Path")
	}
	return nil
}

func (r *Report) validateHeader() error {
	if len(r.ApiHeader) == 0 {
		return utils.NewProxyError("Report.Api.Header", "Empty API Header")
	}
	return nil
}

func (r *Report) validateToken() error {
	if len(r.ApiToken) > 48 || len(r.ApiToken) < 48 {
		return utils.NewProxyError("Report.Api.Token", "Length must be 48")
	}
	return nil
}

func (r *Report) validateUsername() error {
	if len(r.AuthUsername) == 0 {
		return utils.NewProxyError("Report.Auth.Username", "Empty Username")
	}
	return nil
}

func (r *Report) validatePassword() error {
	if len(r.AuthPassword) < 4 {
		return utils.NewProxyError("Report.Auth.Password", "Password length must be greater than or equal 4")
	}
	return nil
}
