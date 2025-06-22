package middlewares

import (
	"madsecurity-defender/services/controllers/proxy/abort"

	"github.com/gin-gonic/gin"
)

func Inspect(managerIp string, maskStatus bool, maskType, maskHtml, maskJson string) gin.HandlerFunc {
	return func(context *gin.Context) {
		if context.RemoteIP() != managerIp {
			if maskStatus {
				if maskType == "html" {
					abort.NotFoundHtml(context, maskHtml)
				}
				if maskType == "json" {
					abort.NotFoundJson(context, maskJson)
				}
				return
			}
			abort.Unauthorized(context)
		}
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
