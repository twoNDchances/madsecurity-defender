package actions

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func Perform(
	context *gin.Context,
	proxy *globals.Proxy,
	target *globals.Target,
	rule *globals.Rule,
	scoreDefault *int,
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
		forceReturn, result = Inspect(context, proxy, rule, scoreDefault)
	case "request":
		forceReturn, result = Request(context, target, rule)
	case "setScore":
		forceReturn, result = SetScore(context, rule, score)
	case "setLevel":
		forceReturn, result = SetLevel(context, rule, level)
	case "report":
		forceReturn, result = Report(context, proxy, target, rule)
	}
	return forceReturn, result
}
