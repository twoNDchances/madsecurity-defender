package middlewares

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"

	"github.com/gin-gonic/gin"
)

func Inspect(security *globals.Security) gin.HandlerFunc {
	return func(context *gin.Context) {
		if context.RemoteIP() != security.ManagerIp {
			if security.MaskStatus {
				if security.MaskType == "html" {
					abort.NotFoundHtml(context, security.MaskHtml)
				}
				if security.MaskType == "json" {
					abort.NotFoundJson(context, security.MaskJson)
				}
			} else {
				abort.Unauthorized(context)
			}
			return
		}
		context.Next()
	}
}

func Authenticate(username, password string) gin.HandlerFunc {
	return func(context *gin.Context) {
		u, p, ok := context.Request.BasicAuth()
		if !ok || u != username || p != password {
			context.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			abort.Unauthorized(context)
			return
		}
		context.Next()
	}
}
