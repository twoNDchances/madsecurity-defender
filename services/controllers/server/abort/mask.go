package abort

import (
	"madsecurity-defender/globals"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Mask(context any) {
	switch ctx := context.(type) {
	case *gin.Context:
		switch globals.SecurityConfigs.MaskType {
		case "html":
			NotFoundHtmlRequest(ctx, globals.SecurityConfigs.MaskHtml)
		case "json":
			NotFoundJsonRequest(ctx, globals.SecurityConfigs.MaskJson)
		}
	case *http.Response:
		switch globals.SecurityConfigs.MaskType {
		case "html":
			NotFoundHtmlResponse(ctx, globals.SecurityConfigs.MaskHtml)
		case "json":
			NotFoundJsonResponse(ctx, globals.SecurityConfigs.MaskJson)
		}
	}
}
