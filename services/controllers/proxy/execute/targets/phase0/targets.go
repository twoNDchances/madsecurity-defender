package phase0

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/services/controllers/proxy/execute/payloads"

	"github.com/gin-gonic/gin"
)

func FullRequest(context *gin.Context, target *globals.Target) string {
	var raw string
	if target.Phase == 0 && target.Alias == "full-request" && target.Name == "raw" && target.Immutable && target.TargetID == nil {
		phase, err := payloads.GetFullPhase(context)
		if err != nil {
			msg := fmt.Sprintf("Target %d: %v", target.ID, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			raw = phase
		}
	}
	return raw
}
