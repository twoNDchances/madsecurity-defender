package routes

import (
	"madsecurity-defender/controllers"
	"madsecurity-defender/globals"
	"madsecurity-defender/middlewares"
	"strings"

	"github.com/gin-gonic/gin"
)

func RouteProxy(router *gin.Engine, proxy *globals.Proxy, security *globals.Security) {
	prefix := router.Group(proxy.Prefix)
	{
		if security.Enable {
			prefix.Use(
				middlewares.Inspect(security),
			)
			prefix.Use(
				middlewares.Authenticate(
					security.Username,
					security.Password,
				),
			)
		}
		prefix.GET(proxy.Health, controllers.ReturnHealth)
		prefix.GET(proxy.Sync, controllers.ReturnSynchronization)
		middlewareController := prefix.Use(
			middlewares.Allow(),
		)
		{
			switch strings.ToLower(proxy.ApplyMethod) {
			case "post":
				middlewareController.POST(proxy.Apply, controllers.ReturnApplication)
			case "put":
				middlewareController.PUT(proxy.Apply, controllers.ReturnApplication)
			case "patch":
				middlewareController.PATCH(proxy.Apply, controllers.ReturnApplication)
			case "delete":
				middlewareController.DELETE(proxy.Apply, controllers.ReturnApplication)
			}
		}
		{
			switch strings.ToLower(proxy.RevokeMethod) {
			case "post":
				middlewareController.POST(proxy.Revoke, controllers.ReturnRevocation)
			case "put":
				middlewareController.PUT(proxy.Revoke, controllers.ReturnRevocation)
			case "patch":
				middlewareController.PATCH(proxy.Revoke, controllers.ReturnRevocation)
			case "delete":
				middlewareController.DELETE(proxy.Revoke, controllers.ReturnRevocation)
			}
		}
	}
}
