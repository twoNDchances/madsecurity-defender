package pass

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute"
	"madsecurity-defender/services/controllers/server/abort"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

func Pass(context *gin.Context) {
	remote, _ := url.Parse(globals.BackendConfigs.BuildUrl())
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Director = func(request *http.Request) {
		request.URL.Scheme = remote.Scheme
		request.URL.Host = remote.Host
		request.URL.Path = fmt.Sprintf("%s%s", globals.BackendConfigs.Path, context.Param("backendPath"))
		request.Host = remote.Host
		request.Header = context.Request.Header.Clone()
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		if result, _ := execute.Execute(response, context); !result {
			abort.Forbidden(response)
		}
		return nil
	}
	proxy.ServeHTTP(context.Writer, context.Request)
}
