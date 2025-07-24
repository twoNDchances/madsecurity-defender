package execute

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"

	"github.com/gin-gonic/gin"
)

func Investigate() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Set("violation_level", uint(globals.ProxyConfigs.ViolationLevel))
		context.Set("current_score", 0)
		context.Set("violation_score", globals.ProxyConfigs.ViolationScore)
		result, render := Execute(context, context)
		if !result {
			if !render {
				context.Abort()
			} else {
				abort.Forbidden(context)
			}
			return
		}
		context.Next()
	}
}
