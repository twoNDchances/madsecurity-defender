package request

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func InvestigateHeader(proxy *globals.Proxy) gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Next()
	}
}

func ExecuteRuleByGroup() {
}
