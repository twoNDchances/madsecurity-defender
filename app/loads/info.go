package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareInfo() (*bool, bool) {
	info, err := utils.ToBoolean(globals.InfoVars["enable"])
	if err != nil {
		log.Println(utils.NewProxyError("Info.Enable", err.Error()))
		return nil, false
	}
	return &info, true
}
