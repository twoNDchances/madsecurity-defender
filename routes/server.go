package routes

import (
	"madsecurity-defender/controllers"
	"madsecurity-defender/globals"
	"madsecurity-defender/middlewares"
	"strings"

	"github.com/gin-gonic/gin"
)

type Route struct {
	method  string
	path    string
	handler gin.HandlerFunc
}

func RouteServer(router *gin.Engine, server *globals.Server, security *globals.Security, storage *globals.Storage) {
	prefix := router.Group(server.Prefix)
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
		prefix.GET(server.Health, controllers.ReturnHealth)
		prefix.GET(server.Sync, controllers.ReturnSynchronization(storage))
		middlewareController := prefix.Use(
			middlewares.Allow(),
		)
		routes := []Route{
			{
				server.ApplyMethod,
				server.Apply,
				controllers.ReturnApplication(storage),
			},
			{
				server.RevokeMethod,
				server.Revoke,
				controllers.ReturnRevocation(storage),
			},
		}
		for _, route := range routes {
			switch strings.ToLower(route.method) {
			case "post":
				middlewareController.POST(route.path, route.handler)
			case "put":
				middlewareController.PUT(route.path, route.handler)
			case "patch":
				middlewareController.PATCH(route.path, route.handler)
			case "delete":
				middlewareController.DELETE(route.path, route.handler)
			}
		}
	}
}
