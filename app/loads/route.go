package loads

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/routes"

	"github.com/gin-gonic/gin"
)

func PrepareServerRoute(router *gin.Engine, server *globals.Server, security *globals.Security, storage *globals.Storage) {
	routes.RouteServer(router, server, security, storage)
}

func PrepareProxyRoute(router *gin.Engine, backend *globals.Backend) {
	routes.RouteProxy(router, backend)
}
