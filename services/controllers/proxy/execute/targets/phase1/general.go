package phase1

import "github.com/gin-gonic/gin"

func GetHeaderData(context *gin.Context) map[string][]string {
	return context.Request.Header
}

func GetUrlArgsData(context *gin.Context) map[string][]string {
	return context.Request.URL.Query()
}
