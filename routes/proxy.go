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
		prefix.Use(
			middlewares.Inspect(
				security.ManagerIp,
				security.MaskStatus,
				security.MaskType,
				security.MaskHtml,
				security.MaskJson,
			),
		)
		if security.Enable {
			prefix.Use(
				middlewares.Authenticate(
					security.Username,
					security.Password,
				),
			)
		}
		prefix.GET(proxy.Health, controllers.ReturnHealth)
		prefix.GET(proxy.Sync)
		prefix.PATCH(proxy.Apply)
		prefix.DELETE(proxy.Revoke)
	}
}
