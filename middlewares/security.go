package middlewares

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"

	"github.com/gin-gonic/gin"
)

func Inspect() gin.HandlerFunc {
	return func(context *gin.Context) {
		if context.RemoteIP() != globals.SecurityConfigs.ManagerIp {
			if globals.SecurityConfigs.MaskEnable {
				abort.Mask(context)
			} else {
				abort.Unauthorized(context)
			}
			return
		}
		context.Next()
	}
}

func Authenticate() gin.HandlerFunc {
	return func(context *gin.Context) {
		u, p, ok := context.Request.BasicAuth()
		if !ok || u != globals.SecurityConfigs.Username || p != globals.SecurityConfigs.Password {
			context.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			abort.Unauthorized(context)
			return
		}
		context.Next()
	}
}
