package phase1

import (
	"madsecurity-defender/globals"
	"net"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func HeaderKeys(context *gin.Context, target *globals.Target) globals.ListString {
	keys := make(globals.ListString, 0)
	if target.Phase == 1 && target.Alias == "header-keys" && target.Name == "keys" && target.Immutable && target.TargetID == nil {
		headers := context.Request.Header
		for key := range headers {
			keys = append(keys, strings.ToLower(key))
		}
	}
	return keys
}

func HeaderValues(context *gin.Context, target *globals.Target) globals.ListString {
	values := make(globals.ListString, 0)
	if target.Phase == 1 && target.Alias == "header-values" && target.Name == "value" && target.Immutable && target.TargetID == nil {
		headers := context.Request.Header
		for _, value := range headers {
			values = append(values, value...)
		}
	}
	return values
}

func UrlArgsKeys(context *gin.Context, target *globals.Target) globals.ListString {
	keys := make(globals.ListString, 0)
	if target.Phase == 1 && target.Alias == "url-args-keys" && target.Name == "keys" && target.Immutable && target.TargetID == nil {
		queries := context.Request.URL.Query()
		for key := range queries {
			keys = append(keys, strings.ToLower(key))
		}
	}
	return keys
}

func UrlArgsValues(context *gin.Context, target *globals.Target) globals.ListString {
	values := make(globals.ListString, 0)
	if target.Phase == 1 && target.Alias == "url-args-values" && target.Name == "values" && target.Immutable && target.TargetID == nil {
		queries := context.Request.URL.Query()
		for _, value := range queries {
			values = append(values, value...)
		}
	}
	return values
}

func HeaderSize(context *gin.Context, target *globals.Target) float64 {
	size := 0.0
	if target.Phase == 1 && target.Alias == "header-size" && target.Name == "size" && target.Immutable && target.TargetID == nil {
		size = float64(len(HeaderKeys(context, target)))
	}
	return size
}

func UrlPort(context *gin.Context, target *globals.Target) float64 {
	port := 0.0
	if target.Phase == 1 && target.Alias == "url-port" && target.Name == "port" && target.Immutable && target.TargetID == nil {
		host := context.Request.Host
		_, portString, err := net.SplitHostPort(host)
		if err != nil {
			context.Error(err)
		} else {
			port, err = strconv.ParseFloat(portString, 64)
			if err != nil {
				context.Error(err)
			}
		}
	}
	return port
}

func UrlArgsSize(context *gin.Context, target *globals.Target) float64 {
	size := 0.0
	if target.Phase == 1 && target.Alias == "url-args-size" && target.Name == "size" && target.Immutable && target.TargetID == nil {
		size = float64(len(UrlArgsKeys(context, target)))
	}
	return size
}

func ClientIp(context *gin.Context, target *globals.Target) string {
	var ip string
	if target.Phase == 1 && target.Alias == "client-ip" && target.Name == "ip" && target.Immutable && target.TargetID == nil {
		ip = context.RemoteIP()
	}
	return ip
}

func ClientMethod(context *gin.Context, target *globals.Target) string {
	var method string
	if target.Phase == 1 && target.Alias == "client-method" && target.Name == "method" && target.Immutable && target.TargetID == nil {
		method = strings.ToLower(context.Request.Method)
	}
	return method
}

func UrlPath(context *gin.Context, target *globals.Target) string {
	var path string
	if target.Phase == 1 && target.Alias == "url-path" && target.Name == "path" && target.Immutable && target.TargetID == nil {
		path = context.Request.URL.Path
	}
	return path
}

func UrlScheme(context *gin.Context, target *globals.Target) string {
	var scheme string
	if target.Phase == 1 && target.Alias == "url-scheme" && target.Name == "scheme" && target.Immutable && target.TargetID == nil {
		scheme = context.Request.URL.Scheme
	}
	return scheme
}

func UrlHost(context *gin.Context, target *globals.Target) string {
	var host string
	if target.Phase == 1 && target.Alias == "url-host" && target.Name == "host" && target.Immutable && target.TargetID == nil {
		host = context.Request.URL.Host
	}
	return host
}
