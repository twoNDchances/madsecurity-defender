package controllers

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/apply"
	"madsecurity-defender/services/controllers/server/health"
	"madsecurity-defender/services/controllers/server/revoke"
	"madsecurity-defender/services/controllers/server/sync"

	"github.com/gin-gonic/gin"
)

func ReturnHealth(context *gin.Context) {
	health.Health(context)
}

func ReturnSynchronization(storage *globals.Storage) gin.HandlerFunc  {
	return func(context *gin.Context) {
		sync.Sync(context, storage)
	}
}

func ReturnApplication(storage *globals.Storage) gin.HandlerFunc {
	return func(context *gin.Context) {
		apply.Apply(context, storage)
	}
}

func ReturnRevocation(storage *globals.Storage) gin.HandlerFunc {
	return func(context *gin.Context) {
		revoke.Revoke(context, storage)
	}
}
