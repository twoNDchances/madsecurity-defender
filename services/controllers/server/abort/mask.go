package abort

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func Mask(context *gin.Context) {
	if globals.SecurityConfigs.MaskType == "html" {
		NotFoundHtml(context, globals.SecurityConfigs.MaskHtml)
	}
	if globals.SecurityConfigs.MaskType == "json" {
		NotFoundJson(context, globals.SecurityConfigs.MaskJson)
	}
}
