package abort

import (
	// "errors"
	"madsecurity-defender/globals"
	"net/http"

	"github.com/gin-gonic/gin"
)

func BadRequest(context *gin.Context, err string) {
	// context.Error(errors.New(err))
	if globals.SecurityConfigs.MaskEnable {
		Mask(context)
		return
	}
	context.AbortWithStatusJSON(
		http.StatusBadRequest,
		gin.H{
			"status": false,
			"message": "bad request",
			"data": nil,
			"error": err,
		},
	)
}
