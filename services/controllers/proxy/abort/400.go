package abort

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func BadRequest(context *gin.Context, err string) {
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
