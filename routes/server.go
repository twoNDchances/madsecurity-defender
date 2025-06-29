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
			prefix.Use(middlewares.Inspect(security))
			prefix.Use(middlewares.Authenticate(security.Username, security.Password, security))
		}
		middlewareController := prefix.Use(
			middlewares.Allow(),
		)
		routes := []Route{
			{
				method:  server.HealthMethod,
				path:    server.Health,
				handler: controllers.ReturnHealth,
			},
			{
				method:  server.SyncMethod,
				path:    server.Sync,
				handler: controllers.ReturnSynchronization(security),
			},
			{
				method:  server.ApplyMethod,
				path:    server.Apply,
				handler: controllers.ReturnApplication(security, storage),
			},
			{
				method:  server.RevokeMethod,
				path:    server.Revoke,
				handler: controllers.ReturnRevocation(security, storage),
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
