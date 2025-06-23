package controllers

import (
	"madsecurity-defender/services/controllers/proxy/health"

	"github.com/gin-gonic/gin"
)

func ReturnHealth(context *gin.Context) {
	health.Health(context)
}

func ReturnApplication(context *gin.Context) {
	
}

func ReturnRevocation(context *gin.Context) {
	
}
