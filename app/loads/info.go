package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareInfo() (*bool, bool) {
	info, err := utils.ToBoolean(globals.AppVars["info.enable"])
	if err != nil {
		promopt := utils.Promopt{
			Module: "App",
			Field: "Info.Enable",
			Kind: "Error",
			Msg: err.Error(),
			Color: utils.RED,
		}
		log.Println(promopt.Error())
		return nil, false
	}
	return &info, true
}
