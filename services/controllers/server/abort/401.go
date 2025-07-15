package abort

import (
	// "errors"
	"madsecurity-defender/globals"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Unauthorized(context *gin.Context) {
	// context.Error(errors.New("basic auth fail"))
	if globals.SecurityConfigs.MaskEnable {
		Mask(context)
		return
	}
	context.AbortWithStatusJSON(
		http.StatusUnauthorized,
		gin.H{
			"status": false,
			"message": "authentication fail",
			"data": nil,
			"error": "credential wrong",
		},
	)
}