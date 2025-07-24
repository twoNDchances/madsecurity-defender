package decisions

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func Perform(context any, contextGin *gin.Context, decision *globals.Decision) (bool, bool, bool, bool) {
	var (
		forceReturn bool
		result      bool
		audit       bool
		render      bool
	)
	switch decision.Action {
	case "deny":
		forceReturn, result, audit, render = Deny(contextGin, decision)
	case "suspect":
		forceReturn, result, audit, render = Suspect(context, contextGin, decision)
	}
	switch decision.PhaseType {
	case "request":
		switch decision.Action {
		case "redirect":
			forceReturn, result, audit, render = Redirect(context.(*gin.Context), decision)
		case "kill":
			forceReturn, result, audit, render = Kill(context.(*gin.Context), decision)
		case "tag":
			forceReturn, result, audit, render = Tag(context.(*gin.Context), decision)
		}
	case "response":
		switch decision.Action {
		}
	}
	return forceReturn, result, audit, render
}
