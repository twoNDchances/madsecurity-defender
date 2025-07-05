package abort

import (
	"errors"
	"madsecurity-defender/globals"
	"net/http"

	"github.com/gin-gonic/gin"
)

func MethodNotAllowed(context *gin.Context) {
	context.Error(errors.New("method mismatch"))
	if globals.SecurityConfigs.MaskEnable {
		Mask(context)
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
