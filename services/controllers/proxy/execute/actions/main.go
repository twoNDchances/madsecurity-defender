package actions

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func Perform(context *gin.Context, group *globals.Group, targetPath []globals.Target, targetValue any, rule *globals.Rule) (bool, bool, bool) {
	var forceReturn, result, audit bool
	switch *rule.Action {
	case "allow":
		forceReturn, result, audit = Allow()
	case "deny":
		forceReturn, result, audit = Deny()
	case "inspect":
		forceReturn, result, audit = Inspect(context, rule)
	case "request":
		forceReturn, result, audit = Request(context, targetPath, targetValue, rule)
	case "setScore":
		forceReturn, result, audit = SetScore(context, rule)
	case "setLevel":
		forceReturn, result, audit = SetLevel(context, rule)
	case "report":
		forceReturn, result, audit = Report(context, group, targetPath, targetValue, rule)
	case "setVariable":
		forceReturn, result, audit = SetVariable(context, rule)
	}
	return forceReturn, result, audit
}
