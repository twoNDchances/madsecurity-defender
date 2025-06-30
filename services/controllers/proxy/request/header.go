package request

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func Investigate(proxy *globals.Proxy) gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Next()
	}
}
