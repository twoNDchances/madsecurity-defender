package routes

import (
	"madsecurity-defender/controllers"
	"madsecurity-defender/globals"
	"madsecurity-defender/middlewares"

	"github.com/gin-gonic/gin"
)

func RouteProxy(router *gin.Engine, proxy *globals.Proxy, security *globals.Security) {
	prefix := router.Group(proxy.Prefix)
	{
		if security.Enable {
			prefix.Use(
				middlewares.Inspect(
					security.ManagerIp,
					security.MaskStatus,
					security.MaskType,
					security.MaskHtml,
					security.MaskJson,
				),
			)
			prefix.Use(
				middlewares.Authenticate(
					security.Username,
					security.Password,
				),
			)
		}
		prefix.GET(proxy.Health, controllers.ReturnHealth)
		prefix.GET(proxy.Sync)
		prefix.Use(middlewares.Allow()).PATCH(proxy.Apply, controllers.ReturnApplication)
		prefix.Use(middlewares.Allow()).DELETE(proxy.Revoke, controllers.ReturnRevocation)
	}
}
