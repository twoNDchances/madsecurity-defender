package middlewares

import (
	"madsecurity-defender/globals"

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
