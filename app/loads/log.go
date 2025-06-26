package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareLog() (*globals.Log, bool) {
	status := true
	consoleEnable, err := utils.ToBoolean(globals.LogVars["console.enable"])
	if err != nil {
		log.Println(utils.NewServerError("Console.Enable", err.Error()))
		status = false
	}
	fileEnable, err := utils.ToBoolean(globals.LogVars["file.enable"])
	if err != nil {
		log.Println(utils.NewServerError("File.Enable", err.Error()))
		status = false
	}
	if !status {
		return nil, status
	}
	logging := globals.Log{
		Console: globals.Console{
			Enable:    consoleEnable,
			Type:      globals.LogVars["console.type"],
			Separator: globals.LogVars["console.separator"],
		},
		File: globals.File{
			Enable:    fileEnable,
			Type:      globals.LogVars["file.type"],
			Name:      globals.LogVars["file.name"],
			Separator: globals.LogVars["file.separator"],
		},
	}
	if errors := logging.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &logging, status
}
