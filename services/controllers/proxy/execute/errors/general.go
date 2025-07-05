package errors

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func WriteErrorTargetLog(msg string) {
	if globals.ProxyConfigs.HistoryErrorEnable {
		errorTreeCauses := globals.ListString{"Proxy", "Target"}
		utils.WriteError(globals.ProxyConfigs.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
	}
}

func WriteErrorEngineLog(msg string) {
	if globals.ProxyConfigs.HistoryErrorEnable {
		errorTreeCauses := globals.ListString{"Proxy", "Target", "Engine"}
		utils.WriteError(globals.ProxyConfigs.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
	}
}

func WriteErrorComparatorLog(msg string) {
	if globals.ProxyConfigs.HistoryErrorEnable {
		errorTreeCauses := globals.ListString{"Proxy", "Rule", "Comparator"}
		utils.WriteError(globals.ProxyConfigs.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
	}
}

func WriteErrorActionLog(msg string) {
	if globals.ProxyConfigs.HistoryErrorEnable {
		errorTreeCauses := globals.ListString{"Proxy", "Rule", "Action"}
		utils.WriteError(globals.ProxyConfigs.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
	}
}

func WriteErrorLogisticLog(msg string) {
	if globals.ProxyConfigs.HistoryErrorEnable {
		errorTreeCauses := globals.ListString{"Proxy", "Rule", "Logistic"}
		utils.WriteError(globals.ProxyConfigs.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
	}
}
