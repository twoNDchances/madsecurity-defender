package middlewares

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"
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

func Check(server *globals.Server, security *globals.Security) gin.HandlerFunc {
	return func(context *gin.Context) {
		correctMethod := true
		switch context.FullPath() {
		case fmt.Sprintf("%s%s", server.Prefix, server.Health):
			if !strings.EqualFold(context.Request.Method, server.HealthMethod) {
				correctMethod = false
			}
		case fmt.Sprintf("%s%s", server.Prefix, server.Sync):
			if !strings.EqualFold(context.Request.Method, server.SyncMethod) {
				correctMethod = false
			}
		case fmt.Sprintf("%s%s", server.Prefix, server.Apply):
			if !strings.EqualFold(context.Request.Method, server.ApplyMethod) {
				correctMethod = false
			}
		case fmt.Sprintf("%s%s", server.Prefix, server.Revoke):
			if !strings.EqualFold(context.Request.Method, server.RevokeMethod) {
				correctMethod = false
			}
		default:
			correctMethod = false
		}
		if !correctMethod {
			if security.MaskEnable {
				abort.Mask(context, security)
			} else {
				abort.MethodNotAllowed(context, security)
			}
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
