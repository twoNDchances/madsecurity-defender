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
	}
	if errors := proxy.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &proxy, status
}
