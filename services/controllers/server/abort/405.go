package abort

import (
	"errors"
	"madsecurity-defender/globals"
	"net/http"

	"github.com/gin-gonic/gin"
)

func MethodNotAllowed(context *gin.Context, security *globals.Security) {
	context.Error(errors.New("method mismatch"))
	if security.MaskEnable {
		Mask(context, security)
		return
	}
	context.AbortWithStatusJSON(
		http.StatusMethodNotAllowed,
		gin.H{
			"status":  false,
			"message": "method not supported",
			"data":    nil,
			"error":   nil,
		},
	)
}
