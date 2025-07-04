package errors

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func WriteErrorTargetLog(proxy *globals.Proxy, msg string) {
	errorTreeCauses := globals.ListString{"Proxy", "Target"}
	utils.WriteError(proxy.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
}

func WriteErrorEngineLog(proxy *globals.Proxy, msg string) {
	errorTreeCauses := globals.ListString{"Proxy", "Target", "Engine"}
	utils.WriteError(proxy.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
}

func WriteErrorComparatorLog(proxy *globals.Proxy, msg string) {
	errorTreeCauses := globals.ListString{"Proxy", "Rule", "Comparator"}
	utils.WriteError(proxy.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
}

func WriteErrorActionLog(proxy *globals.Proxy, msg string) {
	errorTreeCauses := globals.ListString{"Proxy", "Rule", "Action"}
	utils.WriteError(proxy.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
}

func WriteErrorLogisticLog(proxy *globals.Proxy, msg string) {
	errorTreeCauses := globals.ListString{"Proxy", "Rule", "Logistic"}
	utils.WriteError(proxy.HistoryErrorPath, utils.NewErrorCauseName(errorTreeCauses...), msg)
}
