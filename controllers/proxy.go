package controllers

import (
	"madsecurity-defender/services/controllers/proxy/apply"
	"madsecurity-defender/services/controllers/proxy/health"

	"github.com/gin-gonic/gin"
)

func ReturnHealth(context *gin.Context) {
	health.Health(context)
}

func ReturnApplication(context *gin.Context) {
	apply.Apply(context)
}

func ReturnRevocation(context *gin.Context) {
	
}
