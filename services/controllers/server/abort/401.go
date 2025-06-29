package abort

import (
	"errors"
	"madsecurity-defender/globals"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Unauthorized(context *gin.Context, security *globals.Security) {
	context.Error(errors.New("basic auth fail"))
	if security.MaskEnable {
		Mask(context, security)
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