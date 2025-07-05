package controllers

import (
	"madsecurity-defender/services/controllers/proxy/pass"

	"github.com/gin-gonic/gin"
)

func ReturnBackend(context *gin.Context) {
	pass.Pass(context)
}
