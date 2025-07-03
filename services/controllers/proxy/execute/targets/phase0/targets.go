package phase0

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"madsecurity-defender/globals"
	"strings"

	"github.com/gin-gonic/gin"
)

func FullRequest(context *gin.Context, target *globals.Target) string {
	var raw string
	if target.Phase == 0 && target.Alias == "full-request" && target.Name == "raw" && target.Immutable && target.TargetID == nil {
		var headers strings.Builder
		for k, v := range context.Request.Header {
			headers.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
		}
		bodyBytes, err := io.ReadAll(context.Request.Body)
		if err != nil {
			msg := fmt.Sprintf("Target %d: %v", target.ID, err)
			context.Error(errors.New(msg))
		} else {
			context.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			raw = fmt.Sprintf("%s\n%s", headers.String(), string(bodyBytes))
		}
	}
	return raw
}
