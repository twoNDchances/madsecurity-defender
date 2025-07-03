package abort

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Forbidden(context *gin.Context) {
	context.Error(errors.New("forbidden"))
	context.AbortWithStatusJSON(
		http.StatusForbidden,
		gin.H{
			"status":  false,
			"message": "forbidden",
			"data":    nil,
			"error":   "request denied",
		},
	)
}
