package abort

import (
	"errors"
	"madsecurity-defender/globals"
	"net/http"

	"github.com/gin-gonic/gin"
)

func InternalServerError(context *gin.Context, security *globals.Security, err string) {
	context.Error(errors.New(err))
	if security.MaskEnable {
		Mask(context, security)
		return
	}
	context.AbortWithStatusJSON(
		http.StatusInternalServerError,
		gin.H{
			"status":  false,
			"message": "error from server",
			"data":    nil,
			"error":   err,
		},
	)
}
