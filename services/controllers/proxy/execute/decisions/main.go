package decisions

import (
	"madsecurity-defender/globals"
	"net/http"

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
		case "warn":
			forceReturn, result, audit, render = Warn(context.(*http.Response), contextGin, decision)
		case "bait":
			forceReturn, result, audit, render = Bait(context.(*http.Response), contextGin, decision)
		}
	}
	return forceReturn, result, audit, render
}
