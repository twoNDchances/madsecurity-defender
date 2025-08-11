package controllers

import (
	"madsecurity-defender/services/controllers/server/apply"
	"madsecurity-defender/services/controllers/server/health"
	"madsecurity-defender/services/controllers/server/implement"
	"madsecurity-defender/services/controllers/server/inspect"
	"madsecurity-defender/services/controllers/server/revoke"
	"madsecurity-defender/services/controllers/server/suspend"

	"github.com/gin-gonic/gin"
)

func ReturnHealth(context *gin.Context) {
	health.Health(context)
}

func ReturnInspection(context *gin.Context) {
	inspect.Inspect(context)
}

func ReturnApplication(context *gin.Context) {
	apply.Apply(context)
}

func ReturnRevocation(context *gin.Context) {
	revoke.Revoke(context)
}

func ReturnImplementation(context *gin.Context) {
	implement.Implement(context)
}

func ReturnSuspension(context *gin.Context) {
	suspend.Suspend(context)
}
