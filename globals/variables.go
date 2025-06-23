package globals

import (
	"fmt"
	"log"
	"madsecurity-defender/utils"
	"os"
	"slices"
)

var (
	InfoVars = DictString{
		"enable": os.Getenv("DEFENDER_INFO_ENABLE"),
	}

	ProxyVars = DictString{
		"tls":    os.Getenv("DEFENDER_PROXY_TLS"),
		"key":    os.Getenv("DEFENDER_PROXY_KEY"),
		"crt":    os.Getenv("DEFENDER_PROXY_CRT"),
		"host":   os.Getenv("DEFENDER_PROXY_HOST"),
		"port":   os.Getenv("DEFENDER_PROXY_PORT"),
		"prefix": os.Getenv("DEFENDER_PROXY_PREFIX"),
		"health": os.Getenv("DEFENDER_PROXY_HEALTH"),
		"sync":   os.Getenv("DEFENDER_PROXY_SYNC"),
		"apply":  os.Getenv("DEFENDER_PROXY_APPLY"),
		"revoke": os.Getenv("DEFENDER_PROXY_REVOKE"),
	}

	SecurityVars = DictString{
		"enable":     os.Getenv("DEFENDER_PROXY_SECURITY_ENABLE"),
		"username":   os.Getenv("DEFENDER_PROXY_SECURITY_USERNAME"),
		"password":   os.Getenv("DEFENDER_PROXY_SECURITY_PASSWORD"),
		"managerIp":  os.Getenv("DEFENDER_PROXY_SECURITY_MANAGER_IP"),
		"maskStatus": os.Getenv("DEFENDER_PROXY_SECURITY_MASK_STATUS"),
		"maskType":   os.Getenv("DEFENDER_PROXY_SECURITY_MASK_TYPE"),
		"maskHtml":   os.Getenv("DEFENDER_PROXY_SECURITY_MASK_HTML"),
		"maskJson":   os.Getenv("DEFENDER_PROXY_SECURITY_MASK_JSON"),
	}

	LogVars = DictString{
		"console.enable":    os.Getenv("DEFENDER_PROXY_LOG_CONSOLE_ENABLE"),
		"console.type":      os.Getenv("DEFENDER_PROXY_LOG_CONSOLE_TYPE"),
		"console.separator": os.Getenv("DEFENDER_PROXY_LOG_CONSOLE_SEPARATOR"),
		"file.enable":       os.Getenv("DEFENDER_PROXY_LOG_FILE_ENABLE"),
		"file.name":         os.Getenv("DEFENDER_PROXY_LOG_FILE_NAME"),
		"file.type":         os.Getenv("DEFENDER_PROXY_LOG_FILE_TYPE"),
		"file.separator":    os.Getenv("DEFENDER_PROXY_LOG_FILE_SEPARATOR"),
	}

	exclusionVars = ListString{
		"proxy.key",
		"proxy.crt",
		"proxy.host",
		"proxy.prefix",

		"security.username",
		"security.password",
		"security.maskType",
		"security.maskHtml",
		"security.maskJson",

		"log.console.type",
		"log.console.separator",
		"log.file.name",
		"log.file.type",
		"log.file.separator",
	}
)

func CheckEmpty() bool {
	vars := mergeStringMaps(map[string]DictString{
		"info":     InfoVars,
		"proxy":    ProxyVars,
		"security": SecurityVars,
		"log":      LogVars,
	})
	ok := true
	for key, value := range vars {
		if slices.Contains(exclusionVars, key) {
			continue
		}
		if len(value) == 0 {
			promopt := utils.Promopt{
				Module: "Defender",
				Field:  "Variable",
				Kind:   "Empty",
				Msg:    key,
				Color:  utils.RED,
			}
			log.Println(promopt.Error())
			ok = false
		}
	}
	return ok
}

func mergeStringMaps(maps ...map[string]DictString) DictString {
	result := make(DictString)
	for _, m := range maps {
		for key, value := range m {
			for k, v := range value {
				result[fmt.Sprintf("%s.%s", key, k)] = v
			}
		}
	}
	return result
}
