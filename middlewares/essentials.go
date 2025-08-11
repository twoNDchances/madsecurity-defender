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

func Check() gin.HandlerFunc {
	return func(context *gin.Context) {
		correctMethod := true
		switch context.FullPath() {
		case fmt.Sprintf("%s%s", globals.ServerConfigs.Prefix, globals.ServerConfigs.Health):
			if !strings.EqualFold(context.Request.Method, globals.ServerConfigs.HealthMethod) {
				correctMethod = false
			}
		case fmt.Sprintf("%s%s", globals.ServerConfigs.Prefix, globals.ServerConfigs.Inspect):
			if !strings.EqualFold(context.Request.Method, globals.ServerConfigs.InspectMethod) {
				correctMethod = false
			}
		case fmt.Sprintf("%s%s", globals.ServerConfigs.Prefix, globals.ServerConfigs.Apply):
			if !strings.EqualFold(context.Request.Method, globals.ServerConfigs.ApplyMethod) {
				correctMethod = false
			}
		case fmt.Sprintf("%s%s", globals.ServerConfigs.Prefix, globals.ServerConfigs.Revoke):
			if !strings.EqualFold(context.Request.Method, globals.ServerConfigs.RevokeMethod) {
				correctMethod = false
			}
		default:
			correctMethod = false
		}
		if !correctMethod {
			if globals.SecurityConfigs.MaskEnable {
				abort.Mask(context)
			} else {
				abort.MethodNotAllowed(context)
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
