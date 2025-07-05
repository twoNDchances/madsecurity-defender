package execute

import (
	"madsecurity-defender/services/controllers/server/abort"

	"github.com/gin-gonic/gin"
)

func Investigate() gin.HandlerFunc {
	return func(context *gin.Context) {
		if !Request(context) {
			abort.Forbidden(context)
			return
		}
		context.Next()
	}
}
