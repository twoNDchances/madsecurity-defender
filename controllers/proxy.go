package controllers

import (
	"madsecurity-defender/services/controllers/server/apply"
	"madsecurity-defender/services/controllers/server/health"
	"madsecurity-defender/services/controllers/server/revoke"
	"madsecurity-defender/services/controllers/server/sync"

	"github.com/gin-gonic/gin"
)

func ReturnHealth(context *gin.Context) {
	health.Health(context)
}

func ReturnSynchronization(context *gin.Context) {
	sync.Sync(context)
}

func ReturnApplication(context *gin.Context) {
	apply.Apply(context)
}

func ReturnRevocation(context *gin.Context) {
	revoke.Revoke(context)
}
