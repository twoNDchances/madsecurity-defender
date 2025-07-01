package phase0

import (
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func FullRequest(context *gin.Context, target *globals.Target) string {
	var raw string
	if target.Phase == 0 && target.Alias == "full-request" && target.Name == "raw" && target.Immutable && target.TargetID != nil {

	}
	return raw
}
