package loads

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/routes"

	"github.com/gin-gonic/gin"
)

func PrepareRoute(router *gin.Engine, proxy *globals.Proxy, security *globals.Security) {
	routes.RouteProxy(router, proxy, security)
	routes.RouteBackend(router)
}
