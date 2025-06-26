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
	port, err := utils.ToUint(globals.ProxyVars["port"])
	if err != nil {
		log.Println(utils.NewProxyError("Port", err.Error()))
		status = false
	}
	if !status {
		return nil, status
	}
	proxy := globals.Proxy{
		TlsEnable:    enable,
		TlsKey:       globals.ProxyVars["tls.key"],
		TlsCrt:       globals.ProxyVars["tls.crt"],
		Host:         globals.ProxyVars["host"],
		Port:         port,
	}
	if errors := proxy.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &proxy, status
}
