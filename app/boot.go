package app

import (
	"fmt"
	"log"
	"madsecurity-defender/app/info"
	"madsecurity-defender/app/loads"
	"madsecurity-defender/globals"
	"madsecurity-defender/middlewares"
	"madsecurity-defender/utils"

	"github.com/gin-gonic/gin"
)

func Boot() {
	log.Println(utils.NewColor("Preparing...", utils.BLUE))
	if !loads.PrepareVariable() {
		return
	}

	log.Println(utils.NewColor("Validating...", utils.BLUE))
	appInfo, status := loads.PrepareInfo()
	if !status {
		return
	}
	if *appInfo {
		info.NewBanner().Print()
	}

	server, status := loads.PrepareServer()
	if !status {
		return
	}

	logging, status := loads.PrepareLog()
	if !status {
		return
	}

	security, status := loads.PrepareSecurity()
	if !status {
		return
	}

	storage, status := loads.PrepareStorage()
	if !status {
		return
	}

	proxy, status := loads.PrepareProxy()
	if !status {
		return
	}

	backend, status := loads.PrepareBackend()
	if !status {
		return
	}

	if server.Port == proxy.Port {
		log.Println(utils.NewServerError("Port", "Conflict with [Proxy][Port]"))
		return
	}

	gin.SetMode(gin.ReleaseMode)

	go bootServer(server, logging, security, storage)

	go bootProxy(proxy, logging, backend)

	select {}
}

func bootServer(server *globals.Server, logging *globals.Log, security *globals.Security, storage *globals.Storage) {
	defender := gin.New()
	defender.Use(gin.Recovery())
	defender.Use(middlewares.Log(logging))
	defender.Use(middlewares.Prevent())

	defender.HandleMethodNotAllowed = true
	defender.NoMethod(middlewares.Check(server, security))
	loads.PrepareServerRoute(defender, server, security, storage)

	promopt := "Server is listening at"
	address := fmt.Sprintf("%s:%d", server.Host, server.Port)

	run(server.TlsEnable, promopt, address,
		utils.NewServerError("Server", defender.Run(address).Error()),
		utils.NewServerError("Server", defender.RunTLS(address, server.TlsCrt, server.TlsKey).Error()),
	)
}

func bootProxy(proxy *globals.Proxy, logging *globals.Log, backend *globals.Backend) {
	defender := gin.New()
	defender.Use(gin.Recovery())

	defender.Use(middlewares.Log(logging))
	defender.Use(middlewares.Prevent())

	loads.PrepareProxyRoute(defender, backend)

	promopt := "Proxy is listening at"
	address := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)

	run(proxy.TlsEnable, promopt, address,
		utils.NewProxyError("Proxy", defender.Run(address).Error()),
		utils.NewProxyError("Proxy", defender.RunTLS(address, proxy.TlsCrt, proxy.TlsKey).Error()),
	)
}

func run(condition bool, promopt, address string, run, runTLS error) {
	if !condition {
		log.Println(utils.NewColor(fmt.Sprintf("%s %s%s", promopt, "http://", address), utils.YELLOW))
		log.Println(run)
	} else {
		log.Println(utils.NewColor(fmt.Sprintf("%s %s%s", promopt, "https://", address), utils.YELLOW))
		log.Println(runTLS)
	}
}
