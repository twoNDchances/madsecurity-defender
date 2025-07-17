package phase5

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"net/http"
	"strings"
)

func FullResponse(context *http.Response, target *globals.Target) string {
	var raw string
	if target.Phase == 5 && target.Alias == "full-response" && target.Name == "raw" && target.Immutable && target.TargetID == nil {
		var headers strings.Builder
		for key, value := range context.Header {
			headers.WriteString(fmt.Sprintf("%s: %s\n", key, strings.Join(value, ",")))
		}
		bodyBytes, err := utils.DecodeResponseBody(context)
		if err != nil {
			msg := fmt.Sprintf("Target %d: %v", target.ID, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			raw = fmt.Sprintf("%s\n%s\n%s", context.Proto, headers.String(), string(bodyBytes))
		}
	}
	return raw
}
