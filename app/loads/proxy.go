package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareProxy() (*globals.Proxy, bool) {
	status := true
	enable, err := utils.ToBoolean(globals.ProxyVars["tls.enable"])
	if err != nil {
		log.Println(utils.NewProxyError("TLS.Enable", err.Error()))
		status = false
	}
	port, err := utils.ToInt(globals.ProxyVars["port"])
	if err != nil {
		log.Println(utils.NewProxyError("Port", err.Error()))
		status = false
	}
	score, err := utils.ToInt(globals.ProxyVars["violation.score"])
	if err != nil {
		log.Println(utils.NewProxyError("Violation.Score", err.Error()))
		status = false
	}
	level, err := utils.ToInt(globals.ProxyVars["violation.level"])
	if err != nil {
		log.Println(utils.NewProxyError("Violation.Level", err.Error()))
		status = false
	}
	notice, err := utils.ToInt(globals.ProxyVars["severity.notice"])
	if err != nil {
		log.Println(utils.NewProxyError("Severity.Notice", err.Error()))
		status = false
	}
	warning, err := utils.ToInt(globals.ProxyVars["severity.warning"])
	if err != nil {
		log.Println(utils.NewProxyError("Severity.Warning", err.Error()))
		status = false
	}
	erroR, err := utils.ToInt(globals.ProxyVars["severity.error"])
	if err != nil {
		log.Println(utils.NewProxyError("Severity.Error", err.Error()))
		status = false
	}
	critical, err := utils.ToInt(globals.ProxyVars["severity.critical"])
	if err != nil {
		log.Println(utils.NewProxyError("Severity.Critical", err.Error()))
		status = false
	}
	errorEnable, err := utils.ToBoolean(globals.ProxyVars["history.error.enable"])
	if err != nil {
		log.Println(utils.NewProxyError("History.Error.Enable", err.Error()))
		status = false
	}
	if !status {
		return nil, status
	}
	proxy := globals.Proxy{
		Entry: globals.Entry{
			TLS: globals.TLS{
				Enable: enable,
				Key:    globals.ProxyVars["tls.key"],
				Crt:    globals.ProxyVars["tls.crt"],
			},
			Host: globals.ProxyVars["host"],
			Port: port,
		},
		ViolationScore: score,
		ViolationLevel: level,
		Severity: globals.Severity{
			NOTICE:   notice,
			WARNING:  warning,
			ERROR:    erroR,
			CRITICAL: critical,
		},
		HistoryAuditPath:   globals.ProxyVars["history.audit.path"],
		HistoryErrorEnable: errorEnable,
		HistoryErrorPath:   globals.ProxyVars["history.error.path"],
		Report: globals.Report{
			ApiPath:      globals.ProxyVars["report.api.path"],
			ApiHeader:    globals.ProxyVars["report.api.header"],
			ApiToken:     globals.ProxyVars["report.api.token"],
			AuthUsername: globals.ProxyVars["report.auth.username"],
			AuthPassword: globals.ProxyVars["report.auth.password"],
		},
	}
	if errors := proxy.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &proxy, status
}
