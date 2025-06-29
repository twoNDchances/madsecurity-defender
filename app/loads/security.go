package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareSecurity() (*globals.Security, bool) {
	enable, err := utils.ToBoolean(globals.SecurityVars["enable"])
	if err != nil {
		log.Println(utils.NewServerError("Security.Enable", err.Error()))
		return nil, false
	}
	maskEnable, err := utils.ToBoolean(globals.SecurityVars["mask.enable"])
	if err != nil {
		log.Println(utils.NewServerError("Security.Mask.Enable", err.Error()))
		return nil, false
	}
	security := globals.Security{
		Enable:     enable,
		Username:   globals.SecurityVars["username"],
		Password:   globals.SecurityVars["password"],
		ManagerIp:  globals.SecurityVars["manager.ip"],
		MaskEnable: maskEnable,
		MaskType:   globals.SecurityVars["mask.type"],
		MaskHtml:   globals.SecurityVars["mask.html"],
		MaskJson:   globals.SecurityVars["mask.json"],
	}
	if errors := security.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &security, true
}
