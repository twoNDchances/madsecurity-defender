package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareBackend() (*globals.Backend, bool) {
	port, err := utils.ToUint(globals.BackendVars["port"])
	status := true
	if err != nil {
		log.Println(utils.NewProxyError("Backend.Port", err.Error()))
		status = false
	}
	if !status {
		return nil, false
	}
	backend := globals.Backend{
		Scheme: globals.BackendVars["scheme"],
		Host: globals.BackendVars["host"],
		Port: port,
		Path: globals.BackendVars["path"],
	}
	if errors := backend.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &backend, status
}
