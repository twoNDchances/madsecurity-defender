package app

import (
	"fmt"
	"log"
	"madsecurity-defender/app/loads"
	"madsecurity-defender/middlewares"
	"madsecurity-defender/utils"

	"github.com/gin-gonic/gin"
)

func Boot() {
	if !loads.PrepareVariable() {
		return
	}

	proxy, status := loads.PrepareProxy()
	if !status {
		return
	}

	gin.SetMode(gin.ReleaseMode)
	server := gin.New()
	server.Use(gin.Recovery())

	logging, status := loads.PrepareLog()
	if !status {
		return
	}

	server.Use(middlewares.Log(logging))

	security, status := loads.PrepareSecurity()
	if !status {
		return
	}

	loads.PrepareRoute(server, proxy, security)

	address := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
	if !proxy.TLS {
		log.Println(utils.NewProxyError("Server", server.Run(address).Error()))
		return
	}
	// log.Println(utils.NewProxyError("Server"))
}
