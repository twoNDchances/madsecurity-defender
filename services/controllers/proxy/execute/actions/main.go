package actions

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func Perform(
	context *gin.Context,
	proxy *globals.Proxy,
	target *globals.Target,
	targetValue any,
	rule *globals.Rule,
	defaultScore *int,
	score *int,
	level *int,
) (bool, bool) {
	var forceReturn, result bool
	switch *rule.Action {
	case "allow":
		forceReturn, result = Allow()
	case "deny":
		forceReturn, result = Deny()
	case "inspect":
		forceReturn, result = Inspect(context, proxy, rule, defaultScore)
	case "request":
		forceReturn, result = Request(context, targetValue, rule)
	case "setScore":
		forceReturn, result = SetScore(context, rule, score)
	case "setLevel":
		forceReturn, result = SetLevel(context, rule, level)
	case "report":
		forceReturn, result = Report(context, proxy, targetValue, rule)
	}
	return forceReturn, result
}
