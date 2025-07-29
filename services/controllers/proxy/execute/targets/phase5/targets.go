package phase5

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/services/controllers/proxy/execute/payloads"
	"net/http"
)

func FullResponse(context *http.Response, target *globals.Target) string {
	var raw string
	if target.Phase == 5 && target.Alias == "full-response" && target.Name == "raw" && target.Immutable && target.TargetID == nil {
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
