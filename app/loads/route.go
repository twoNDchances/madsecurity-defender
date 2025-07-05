package loads

import (
	"madsecurity-defender/routes"

	"github.com/gin-gonic/gin"
)

func PrepareServerRoute(router *gin.Engine) {
	routes.RouteServer(router)
}

func PrepareProxyRoute(router *gin.Engine) {
	routes.RouteProxy(router)
}
