package controllers

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/pass"

	"github.com/gin-gonic/gin"
)

func ReturnBackend(backend *globals.Backend) gin.HandlerFunc {
	return func(context *gin.Context) {
		pass.Pass(context, backend)
	}
}
