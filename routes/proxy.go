package routes

import (
	"madsecurity-defender/controllers"
	"madsecurity-defender/services/controllers/proxy/execute"

	"github.com/gin-gonic/gin"
)

func RouteProxy(router *gin.Engine) {
	investigation := router.Use(
		execute.Investigate(),
	)
	{
		investigation.Any("/*backendPath", controllers.ReturnBackend)
	}
}
