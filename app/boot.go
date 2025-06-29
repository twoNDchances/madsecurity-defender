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

	if server.Entry.Port == proxy.Entry.Port {
		log.Println(utils.NewServerError("Port", "Conflict with [Proxy][Port]"))
		return
	}

	log.Println(utils.NewColor(fmt.Sprintf("Storage in use is %s", storage.Type), utils.BLUE))

	gin.SetMode(gin.ReleaseMode)

	go bootServer(server, logging, security, storage)

	go bootProxy(proxy, logging, storage, backend)

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

	promopt("Server", defender, server)
}

func bootProxy(proxy *globals.Proxy, logging *globals.Log, storage *globals.Storage, backend *globals.Backend) {
	defender := gin.New()
	defender.Use(gin.Recovery())

	defender.Use(middlewares.Log(logging))
	defender.Use(middlewares.Prevent())

	loads.PrepareProxyRoute(defender, proxy, storage, backend)

	promopt("Proxy", defender, proxy)
}

func promopt[T globals.Instructable](entryName string, engine *gin.Engine, entryType T) {
	var boot func() error
	promopt := func(scheme string) string {
		return utils.NewColor(fmt.Sprintf(
			"%s is serving at %s://%s:%d",
			entryName,
			scheme,
			entryType.GetEntry().Host,
			entryType.GetEntry().Port,
		), utils.YELLOW)
	}
	address := fmt.Sprintf("%s:%d", entryType.GetEntry().Host, entryType.GetEntry().Port)
	if entryType.GetEntry().TLS.Enable {
		log.Println(promopt("https"))
		boot = func() error {
			return utils.NewProxyError(
				entryName,
				engine.RunTLS(
					address,
					entryType.GetEntry().TLS.Crt,
					entryType.GetEntry().TLS.Key,
				).Error(),
			)
		}
	} else {
		log.Println(promopt("http"))
		boot = func() error {
			return utils.NewProxyError(
				entryName,
				engine.Run(address).Error(),
			)
		}
	}
	log.Println(boot())
}
