package routes

import (
	"madsecurity-defender/controllers"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/request"

	"github.com/gin-gonic/gin"
)

func RouteProxy(router *gin.Engine, proxy *globals.Proxy, storage *globals.Storage, backend *globals.Backend) {
	investigation := router.Use(
		request.Investigate(proxy),
	)
	{
		investigation.Any("/*backendPath", controllers.ReturnBackend(backend))
	}
}
