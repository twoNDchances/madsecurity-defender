package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareProxy() (*globals.Proxy, bool) {
	status := true
	tls, err := utils.ToBoolean(globals.ProxyVars["tls"])
	if err != nil {
		log.Println(utils.NewProxyError("TLS", err.Error()))
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
		TLS:          tls,
		Key:          globals.ProxyVars["key"],
		Crt:          globals.ProxyVars["crt"],
		Host:         globals.ProxyVars["host"],
		Port:         port,
		Prefix:       globals.ProxyVars["prefix"],
		Health:       globals.ProxyVars["health"],
		Sync:         globals.ProxyVars["sync"],
		Apply:        globals.ProxyVars["apply"],
		ApplyMethod:  globals.ProxyVars["apply.method"],
		Revoke:       globals.ProxyVars["revoke"],
		RevokeMethod: globals.ProxyVars["revoke.method"],
	}
	if errors := proxy.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &proxy, status
}
