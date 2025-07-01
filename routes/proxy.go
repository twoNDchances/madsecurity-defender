package routes

import (
	"madsecurity-defender/controllers"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute"

	"github.com/gin-gonic/gin"
)

func RouteProxy(router *gin.Engine, proxy *globals.Proxy, storage *globals.Storage, backend *globals.Backend) {
	investigation := router.Use(
		execute.Investigate(proxy),
	)
	{
		investigation.Any("/*backendPath", controllers.ReturnBackend(backend))
	}
}
