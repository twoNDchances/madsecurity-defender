package abort

import (
	// "errors"
	"madsecurity-defender/globals"
	"net/http"

	"github.com/gin-gonic/gin"
)

func InternalServerError(context *gin.Context, err string) {
	// context.Error(errors.New(err))
	if globals.SecurityConfigs.MaskEnable {
		Mask(context)
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
