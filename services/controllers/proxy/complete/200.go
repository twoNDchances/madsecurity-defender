package complete

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func OK(context *gin.Context, message string, data any) {
	context.JSON(
		http.StatusOK,
		gin.H{
			"status": false,
			"message": "",
			"data": nil,
			"error": nil,
		},
	)
}
