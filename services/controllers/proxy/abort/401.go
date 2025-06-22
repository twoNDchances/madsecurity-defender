package abort

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Unauthorized(context *gin.Context) {
	context.AbortWithStatusJSON(
		http.StatusUnauthorized,
		gin.H{
			"status": false,
			"message": "authentication fail",
			"data": nil,
		},
	)
}