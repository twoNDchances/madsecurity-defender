package decisions

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func Deny(context *gin.Context, decision *globals.Decision) (bool, bool, bool) {
	var (
		forceReturn bool
		result      bool
		logistic    bool
	)
	if context.GetInt("current_score") < context.GetInt("violation_score") {
		forceReturn = true
		result = false
		logistic = true
	}
	return forceReturn, result, logistic
}


