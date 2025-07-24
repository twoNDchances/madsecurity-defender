package decisions

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func Perform(context any, decision *globals.Decision) (bool, bool, bool, bool) {
	var (
		forceReturn bool
		result      bool
		logistic    bool
		render      bool
	)
	switch decision.PhaseType {
	case "request":
		switch decision.Action {
			case "deny":z
				forceReturn, result, logistic, render = Deny(context.(*gin.Context), decision)
			case "suspect":
				forceReturn, result, logistic, render = Suspect(context, decision)
			case "redirect":
				forceReturn, result, logistic, render = Redirect(context.(*gin.Context), decision)
			case "kill":
				forceReturn, result, logistic, render = Kill(decision)
			case "tag":
				forceReturn, result, logistic, render = Tag(context.(*gin.Context), decision)
		}
	case "response":
	}
	return forceReturn, result, logistic, render
}
