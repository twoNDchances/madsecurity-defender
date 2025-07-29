package payloads

import (
	"bytes"
	"fmt"
	"io"
	"madsecurity-defender/utils"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func GetFullPhase(context any) (string, error) {
	var raw string
	var headers strings.Builder
	switch ctx := context.(type) {
	case *gin.Context:
		for key, value := range ctx.Request.Header {
			headers.WriteString(fmt.Sprintf("%s: %s\n", key, strings.Join(value, ",")))
		}
		bodyBytes, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			return "", err
		} else {
			ctx.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			raw = fmt.Sprintf("%s\n%s\n%s", ctx.Request.Proto, headers.String(), string(bodyBytes))
		}
	case *http.Response:
		for key, value := range ctx.Header {
			headers.WriteString(fmt.Sprintf("%s: %s\n", key, strings.Join(value, ",")))
		}
		bodyBytes, err := utils.DecodeResponseBody(ctx)
		if err != nil {
			return "", err
		} else {
			raw = fmt.Sprintf("%s\n%s\n%s", ctx.Proto, headers.String(), string(bodyBytes))
		}
	}
	return raw, nil
}
