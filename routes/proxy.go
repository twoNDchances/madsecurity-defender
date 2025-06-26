package routes

import (
	"madsecurity-defender/controllers"
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func RouteProxy(router *gin.Engine, backend *globals.Backend) {
	router.Use().Any("/*backendPath", controllers.ReturnBackend(backend))
}