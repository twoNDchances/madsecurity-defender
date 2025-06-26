package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareServer() (*globals.Server, bool) {
	status := true
	enable, err := utils.ToBoolean(globals.ServerVars["tls.enable"])
	if err != nil {
		log.Println(utils.NewServerError("TLS.Enable", err.Error()))
		status = false
	}
	port, err := utils.ToUint(globals.ServerVars["port"])
	if err != nil {
		log.Println(utils.NewServerError("Port", err.Error()))
		status = false
	}
	if !status {
		return nil, status
	}
	server := globals.Server{
		TlsEnable:    enable,
		TlsKey:       globals.ServerVars["tls.key"],
		TlsCrt:       globals.ServerVars["tls.crt"],
		Host:         globals.ServerVars["host"],
		Port:         port,
		Prefix:       globals.ServerVars["prefix"],
		Health:       globals.ServerVars["health"],
		Sync:         globals.ServerVars["sync"],
		Apply:        globals.ServerVars["apply"],
		ApplyMethod:  globals.ServerVars["apply.method"],
		Revoke:       globals.ServerVars["revoke"],
		RevokeMethod: globals.ServerVars["revoke.method"],
	}
	if errors := server.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &server, status
}
