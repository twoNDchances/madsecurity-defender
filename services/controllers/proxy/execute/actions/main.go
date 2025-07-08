package actions

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func Perform(
	context *gin.Context,
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
		forceReturn, result = Inspect(rule, defaultScore)
	case "request":
		forceReturn, result = Request(targetValue, rule)
	case "setScore":
		forceReturn, result = SetScore(rule, score)
	case "setLevel":
		forceReturn, result = SetLevel(rule, level)
	case "report":
		forceReturn, result = Report(targetValue, rule)
	case "setVariable":
		forceReturn, result = SetVariable(context, rule)
	}
	return forceReturn, result
}
