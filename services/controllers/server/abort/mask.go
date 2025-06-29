package abort

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func Mask(context *gin.Context, security *globals.Security) {
	if security.MaskType == "html" {
		NotFoundHtml(context, security.MaskHtml)
	}
	if security.MaskType == "json" {
		NotFoundJson(context, security.MaskJson)
	}
}
