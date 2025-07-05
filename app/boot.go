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

	globals.ServerConfigs, status = loads.PrepareServer()
	if !status {
		return
	}

	globals.LogConfigs, status = loads.PrepareLog()
	if !status {
		return
	}

	globals.SecurityConfigs, status = loads.PrepareSecurity()
	if !status {
		return
	}

	globals.StorageConfigs, status = loads.PrepareStorage()
	if !status {
		return
	}

	globals.ProxyConfigs, status = loads.PrepareProxy()
	if !status {
		return
	}

	globals.BackendConfigs, status = loads.PrepareBackend()
	if !status {
		return
	}

	if globals.ServerConfigs.Entry.Port == globals.ProxyConfigs.Entry.Port {
		log.Println(utils.NewServerError("Port", "Conflict with [Proxy][Port]"))
		return
	}

	log.Println(utils.NewColor(fmt.Sprintf("Storage in use is %s", globals.StorageConfigs.Type), utils.BLUE))

	gin.SetMode(gin.ReleaseMode)

	go bootServer()

	go bootProxy()

	select {}
}

func bootServer() {
	defender := gin.New()
	defender.Use(gin.Recovery())
	defender.Use(middlewares.Log())
	defender.Use(middlewares.Prevent())

	defender.HandleMethodNotAllowed = true
	defender.NoMethod(middlewares.Check())
	loads.PrepareServerRoute(defender)

	promopt("Server", defender, globals.ServerConfigs)
}

func bootProxy() {
	defender := gin.New()
	defender.Use(gin.Recovery())

	defender.Use(middlewares.Log())
	defender.Use(middlewares.Prevent())

	loads.PrepareProxyRoute(defender)

	promopt("Proxy", defender, globals.ProxyConfigs)
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
