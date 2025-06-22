package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareSecurity() (*globals.Security, bool) {
	enable, err := utils.ToBoolean(globals.SecurityVars["enable"])
	if err != nil {
		log.Println(utils.NewProxyError("Security.Enable", err.Error()))
		return nil, false
	}
	maskStatus, err := utils.ToBoolean(globals.SecurityVars["maskStatus"])
	if err != nil {
		log.Println(utils.NewProxyError("Security.MaskStatus", err.Error()))
		return nil, false
	}
	security := globals.Security{
		Enable:     enable,
		Username:   globals.SecurityVars["username"],
		Password:   globals.SecurityVars["password"],
		ManagerIp:  globals.SecurityVars["managerIp"],
		MaskStatus: maskStatus,
		MaskType:   globals.SecurityVars["maskType"],
		MaskHtml:   globals.SecurityVars["maskHtml"],
		MaskJson:   globals.SecurityVars["maskJson"],
	}
	if errors := security.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &security, true
}
