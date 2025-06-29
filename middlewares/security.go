package middlewares

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"

	"github.com/gin-gonic/gin"
)

func Inspect(security *globals.Security) gin.HandlerFunc {
	return func(context *gin.Context) {
		if context.RemoteIP() != security.ManagerIp {
			if security.MaskEnable {
				abort.Mask(context, security)
			} else {
				abort.Unauthorized(context, security)
			}
			return
		}
		context.Next()
	}
}

func Authenticate(username, password string, security *globals.Security) gin.HandlerFunc {
	return func(context *gin.Context) {
		u, p, ok := context.Request.BasicAuth()
		if !ok || u != username || p != password {
			context.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			abort.Unauthorized(context, security)
			return
		}
		context.Next()
	}
}
