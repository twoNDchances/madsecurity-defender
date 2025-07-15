package abort

import (
	// "errors"
	"madsecurity-defender/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

func NotFoundJson(context *gin.Context, path string) {
	// context.Error(errors.New("page not exists"))
	var response gin.H
	if err := utils.ReadJson(path, &response); err != nil {
		response = gin.H{
			"status": false,
			"message": "not found",
			"data": nil,
			"error": "page not exists",
		}
	}
	context.AbortWithStatusJSON(http.StatusNotFound, response)
}

func NotFoundHtml(context *gin.Context, path string) {
	data, err := utils.ReadFile(path)
	statusCode := http.StatusNotFound
	contentType := "text/html; charset=utf-8"
	response := data
	if err != nil {
		defaultPath := "services/controllers/server/abort/public/404.default.html"
		defaultData, _ := utils.ReadFile(defaultPath)
		response = defaultData
	}
	// context.Error(errors.New("page not exists"))
	context.Data(statusCode, contentType, response)
	context.Abort()
}
