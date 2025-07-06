package errors

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func writeError(msg string, errorTreeCauses ...string) {
	if !globals.ProxyConfigs.HistoryErrorEnable {
		return
	}
	utils.WriteError(globals.ProxyConfigs.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
}

func WriteErrorTargetLog(msg string) {
	writeError(msg, globals.ListString{"Proxy", "Target"}...)
}

func WriteErrorEngineLog(msg string) {
	writeError(msg, globals.ListString{"Proxy", "Target", "Engine"}...)
}

func WriteErrorComparatorLog(msg string) {
	writeError(msg, globals.ListString{"Proxy", "Rule", "Comparator"}...)
}

func WriteErrorActionLog(msg string) {
	writeError(msg, globals.ListString{"Proxy", "Rule", "Action"}...)
}

func WriteErrorLogisticLog(msg string) {
	writeError(msg, globals.ListString{"Proxy", "Rule", "Logistic"}...)
}
