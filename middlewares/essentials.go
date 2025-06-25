package middlewares

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/abort"
	"strings"

	"github.com/gin-gonic/gin"
)

func Prevent() gin.HandlerFunc {
	return func(context *gin.Context) {
		globals.PauseMtx.Lock()
		for globals.IsPaused {
			globals.PauseCnd.Wait()
		}
		globals.PauseMtx.Unlock()
		context.Next()
	}
}

func Check(proxy *globals.Proxy, security *globals.Security) gin.HandlerFunc {
	return func(context *gin.Context) {
		correctMethod := true
		switch context.FullPath() {
		case fmt.Sprintf("%s%s", proxy.Prefix, proxy.Apply):
			if !strings.EqualFold(context.Request.Method, proxy.ApplyMethod) {
				correctMethod = false
			}
		case fmt.Sprintf("%s%s", proxy.Prefix, proxy.Revoke):
			if !strings.EqualFold(context.Request.Method, proxy.RevokeMethod) {
				correctMethod = false
			}
		default:
			correctMethod = false
		}
		if !correctMethod {
			if security.MaskStatus {
				if security.MaskType == "html" {
					abort.NotFoundHtml(context, security.MaskHtml)
				}
				if security.MaskType == "json" {
					abort.NotFoundJson(context, security.MaskJson)
				}
			}
			abort.MethodNotAllowed(context)
			return
		}
		context.Next()
	}
}

func Allow() gin.HandlerFunc {
	return func(context *gin.Context) {
		globals.PauseMtx.Lock()
		globals.IsPaused = true
		globals.PauseMtx.Unlock()

		context.Next()

		globals.PauseMtx.Lock()
		globals.IsPaused = false
		globals.PauseCnd.Broadcast()
		globals.PauseMtx.Unlock()
	}
}
