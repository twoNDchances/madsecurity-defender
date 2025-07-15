package abort

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func Forbidden(context any) {
	switch ctx := context.(type) {
	case *gin.Context:
		ctx.AbortWithStatusJSON(
			http.StatusForbidden,
			gin.H{
				"status":  false,
				"message": "forbidden",
				"data":    nil,
				"error":   "request denied",
			},
		)
	case *http.Response:
		body := `{"status":false,"message":"forbidden","data":null,"error":"request denied"}`
		ctx.StatusCode = http.StatusForbidden
		ctx.Status = "403 Forbidden"
		if len(ctx.Header.Get("Content-Encoding")) > 0 {
			ctx.Header.Del("Content-Encoding")
		}
		ctx.Header.Set("Content-Type", "application/json")
		ctx.Header.Set("Content-Length", fmt.Sprint(len(body)))
		ctx.ContentLength = int64(len(body))
		ctx.Body = io.NopCloser(strings.NewReader(body))
	}
}
