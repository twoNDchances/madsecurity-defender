package abort

import (
	// "errors"
	"encoding/json"
	"fmt"
	"io"
	"madsecurity-defender/utils"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func NotFoundJsonRequest(context *gin.Context, path string) {
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

func NotFoundHtmlRequest(context *gin.Context, path string) {
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

func NotFoundJsonResponse(context *http.Response, path string) {
	var response gin.H
	if err := utils.ReadJson(path, &response); err != nil {
		response = gin.H{
			"status": false,
			"message": "not found",
			"data": nil,
			"error": "page not exists",
		}
	}
	bodyBytes, err := json.Marshal(response)
	if err != nil {
		bodyBytes = []byte(`{"status":false,"message":"not found","error":"internal error"}`)
	}
	context.Header.Set("Content-Type", "application/json")
	prepareResponse(context, string(bodyBytes))
}

func NotFoundHtmlResponse(context *http.Response, path string) {
	data, err := utils.ReadFile(path)
	if err != nil {
		defaultPath := "services/controllers/server/abort/public/404.default.html"
		defaultData, _ := utils.ReadFile(defaultPath)
		data = defaultData
	}
	context.Header.Set("Content-Type", "text/html; charset=utf-8")
	prepareResponse(context, string(data))
}

func prepareResponse(context *http.Response, body string) {
	context.StatusCode = http.StatusNotFound
	context.Status = "404 Not Found"
	if len(context.Header.Get("Content-Encoding")) > 0 {
		context.Header.Del("Content-Encoding")
	}
	context.Header.Set("Content-Length", fmt.Sprint(len(body)))
	context.ContentLength = int64(len(body))
	context.Body = io.NopCloser(strings.NewReader(body))
}
