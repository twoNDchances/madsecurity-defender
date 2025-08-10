package middlewares

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"
	"net"

	"github.com/gin-gonic/gin"
)

func Inspect() gin.HandlerFunc {
	return func(context *gin.Context) {
		match := true
		clientIP := net.ParseIP(context.ClientIP())
		if clientIP == nil {
			match = false
		} else {
			if ip := net.ParseIP(globals.SecurityConfigs.ManagerHost); ip != nil {
				match = ip.Equal(clientIP)
			} else {
				ips, err := net.LookupIP(globals.SecurityConfigs.ManagerHost)
				if err != nil {
					match = false
				} else {
					for _, ip := range ips {
						if ip.Equal(clientIP) {
							match = true
							break
						}
					}
				}
			}
		}
		if !match {
			if globals.SecurityConfigs.MaskEnable {
				abort.Mask(context)
			} else {
				abort.Unauthorized(context)
			}
			return
		}
		context.Next()
	}
}

func Authenticate() gin.HandlerFunc {
	return func(context *gin.Context) {
		u, p, ok := context.Request.BasicAuth()
		if !ok || u != globals.SecurityConfigs.Username || p != globals.SecurityConfigs.Password {
			context.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			abort.Unauthorized(context)
			return
		}
		context.Next()
	}
}
