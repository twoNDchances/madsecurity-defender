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
	port, err := utils.ToInt(globals.ServerVars["port"])
	if err != nil {
		log.Println(utils.NewServerError("Port", err.Error()))
		status = false
	}
	if !status {
		return nil, status
	}
	server := globals.Server{
		Entry: globals.Entry{
			TLS: globals.TLS{
				Enable: enable,
				Key:    globals.ServerVars["tls.key"],
				Crt:    globals.ServerVars["tls.crt"],
			},
			Host: globals.ServerVars["host"],
			Port: port,
		},
		Prefix:          globals.ServerVars["prefix"],
		Health:          globals.ServerVars["health"],
		HealthMethod:    globals.ServerVars["health.method"],
		Sync:            globals.ServerVars["sync"],
		SyncMethod:      globals.ServerVars["sync.method"],
		Apply:           globals.ServerVars["apply"],
		ApplyMethod:     globals.ServerVars["apply.method"],
		Revoke:          globals.ServerVars["revoke"],
		RevokeMethod:    globals.ServerVars["revoke.method"],
		Implement:       globals.ServerVars["implement"],
		ImplementMethod: globals.ServerVars["implement.method"],
		Suspend:         globals.ServerVars["suspend"],
		SuspendMethod:   globals.ServerVars["suspend.method"],
	}
	if errors := server.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &server, status
}
