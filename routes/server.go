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

func RouteServer(router *gin.Engine) {
	prefix := router.Group(globals.ServerConfigs.Prefix)
	{
		if globals.SecurityConfigs.Enable {
			prefix.Use(middlewares.Inspect())
			prefix.Use(middlewares.Authenticate())
		}
		middlewareController := prefix.Use(
			middlewares.Allow(),
		)
		routes := []Route{
			{
				method:  globals.ServerConfigs.HealthMethod,
				path:    globals.ServerConfigs.Health,
				handler: controllers.ReturnHealth,
			},
			{
				method:  globals.ServerConfigs.InspectMethod,
				path:    globals.ServerConfigs.Inspect,
				handler: controllers.ReturnInspection,
			},
			{
				method:  globals.ServerConfigs.ApplyMethod,
				path:    globals.ServerConfigs.Apply,
				handler: controllers.ReturnApplication,
			},
			{
				method:  globals.ServerConfigs.RevokeMethod,
				path:    globals.ServerConfigs.Revoke,
				handler: controllers.ReturnRevocation,
			},
			{
				method:  globals.ServerConfigs.ImplementMethod,
				path:    globals.ServerConfigs.Implement,
				handler: controllers.ReturnImplementation,
			},
			{
				method:  globals.ServerConfigs.SuspendMethod,
				path:    globals.ServerConfigs.Suspend,
				handler: controllers.ReturnSuspension,
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
