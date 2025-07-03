package execute

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"

	"github.com/gin-gonic/gin"
)

func Investigate(proxy *globals.Proxy) gin.HandlerFunc {
	return func(context *gin.Context) {
		if !Request(context, proxy) {
			abort.Forbidden(context)
			return
		}
		context.Next()
	}
}
