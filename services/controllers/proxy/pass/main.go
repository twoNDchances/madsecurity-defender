package pass

import (
	"bytes"
	"fmt"
	"io"
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

		// var bodyBytes []byte
		// bodyBytes, _ = io.ReadAll(context.Request.Body)
		// context.Request.Body.Close()
		//
		// context.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		// request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		// request.ContentLength = int64(len(bodyBytes))
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		//
		response.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return nil
	}
	proxy.ServeHTTP(context.Writer, context.Request)
}
