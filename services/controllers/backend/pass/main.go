package pass

import (
	"fmt"
	"madsecurity-defender/globals"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

func Pass(context *gin.Context, backend *globals.Backend) {
	remote, _ := url.Parse(backend.BuildUrl())
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Director = func(request *http.Request) {
		request.URL.Scheme = remote.Scheme
		request.URL.Host = remote.Host
		request.URL.Path = fmt.Sprintf("%s%s", backend.Path, context.Param("backendPath"))
		request.Host = remote.Host
		request.Header = context.Request.Header.Clone()
	}
	proxy.ServeHTTP(context.Writer, context.Request)
}
