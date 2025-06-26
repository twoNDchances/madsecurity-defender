package abort

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func MethodNotAllowed(context *gin.Context) {
	context.AbortWithStatusJSON(
		http.StatusMethodNotAllowed,
		gin.H{
			"status": false,
			"message": "method not supported",
			"data": nil,
			"error": nil,
		},
	)
}
