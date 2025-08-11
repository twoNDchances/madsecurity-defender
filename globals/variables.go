package globals

import (
	"fmt"
	"log"
	"madsecurity-defender/utils"
	"os"
	"slices"
)

var (
	AppVars = DictString{
		"info.enable": os.Getenv("DEFENDER_APP_INFO_ENABLE"),
	}

	ServerVars = DictString{
		"tls.enable":       os.Getenv("DEFENDER_SERVER_TLS_ENABLE"),
		"tls.key":          os.Getenv("DEFENDER_SERVER_TLS_KEY"),
		"tls.crt":          os.Getenv("DEFENDER_SERVER_TLS_CRT"),
		"host":             os.Getenv("DEFENDER_SERVER_HOST"),
		"port":             os.Getenv("DEFENDER_SERVER_PORT"),
		"prefix":           os.Getenv("DEFENDER_SERVER_PREFIX"),
		"health":           os.Getenv("DEFENDER_SERVER_HEALTH"),
		"health.method":    os.Getenv("DEFENDER_SERVER_HEALTH_METHOD"),
		"inspect":          os.Getenv("DEFENDER_SERVER_INSPECT"),
		"inspect.method":   os.Getenv("DEFENDER_SERVER_INSPECT_METHOD"),
		"apply":            os.Getenv("DEFENDER_SERVER_APPLY"),
		"apply.method":     os.Getenv("DEFENDER_SERVER_APPLY_METHOD"),
		"revoke":           os.Getenv("DEFENDER_SERVER_REVOKE"),
		"revoke.method":    os.Getenv("DEFENDER_SERVER_REVOKE_METHOD"),
		"implement":        os.Getenv("DEFENDER_SERVER_IMPLEMENT"),
		"implement.method": os.Getenv("DEFENDER_SERVER_IMPLEMENT_METHOD"),
		"suspend":          os.Getenv("DEFENDER_SERVER_SUSPEND"),
		"suspend.method":   os.Getenv("DEFENDER_SERVER_SUSPEND_METHOD"),
	}

	SecurityVars = DictString{
		"manager.host": os.Getenv("DEFENDER_SERVER_SECURITY_MANAGER_HOST"),
		"enable":       os.Getenv("DEFENDER_SERVER_SECURITY_ENABLE"),
		"username":     os.Getenv("DEFENDER_SERVER_SECURITY_USERNAME"),
		"password":     os.Getenv("DEFENDER_SERVER_SECURITY_PASSWORD"),
		"mask.enable":  os.Getenv("DEFENDER_SERVER_SECURITY_MASK_ENABLE"),
		"mask.type":    os.Getenv("DEFENDER_SERVER_SECURITY_MASK_TYPE"),
		"mask.html":    os.Getenv("DEFENDER_SERVER_SECURITY_MASK_HTML"),
		"mask.json":    os.Getenv("DEFENDER_SERVER_SECURITY_MASK_JSON"),
	}

	LogVars = DictString{
		"console.enable":    os.Getenv("DEFENDER_SERVER_LOG_CONSOLE_ENABLE"),
		"console.type":      os.Getenv("DEFENDER_SERVER_LOG_CONSOLE_TYPE"),
		"console.separator": os.Getenv("DEFENDER_SERVER_LOG_CONSOLE_SEPARATOR"),
		"file.enable":       os.Getenv("DEFENDER_SERVER_LOG_FILE_ENABLE"),
		"file.name":         os.Getenv("DEFENDER_SERVER_LOG_FILE_NAME"),
		"file.type":         os.Getenv("DEFENDER_SERVER_LOG_FILE_TYPE"),
		"file.separator":    os.Getenv("DEFENDER_SERVER_LOG_FILE_SEPARATOR"),
	}

	StorageVars = DictString{
		"type":           os.Getenv("DEFENDER_SERVER_STORAGE_TYPE"),
		"redis.host":     os.Getenv("DEFENDER_SERVER_STORAGE_REDIS_HOST"),
		"redis.port":     os.Getenv("DEFENDER_SERVER_STORAGE_REDIS_PORT"),
		"redis.password": os.Getenv("DEFENDER_SERVER_STORAGE_REDIS_PASSWORD"),
		"redis.database": os.Getenv("DEFENDER_SERVER_STORAGE_REDIS_DATABASE"),
	}

	ProxyVars = DictString{
		"tls.enable":           os.Getenv("DEFENDER_PROXY_TLS_ENABLE"),
		"tls.key":              os.Getenv("DEFENDER_PROXY_TLS_KEY"),
		"tls.crt":              os.Getenv("DEFENDER_PROXY_TLS_CRT"),
		"host":                 os.Getenv("DEFENDER_PROXY_HOST"),
		"port":                 os.Getenv("DEFENDER_PROXY_PORT"),
		"violation.score":      os.Getenv("DEFENDER_PROXY_VIOLATION_SCORE"),
		"violation.level":      os.Getenv("DEFENDER_PROXY_VIOLATION_LEVEL"),
		"severity.notice":      os.Getenv("DEFENDER_PROXY_SEVERITY_NOTICE"),
		"severity.warning":     os.Getenv("DEFENDER_PROXY_SEVERITY_WARNING"),
		"severity.error":       os.Getenv("DEFENDER_PROXY_SEVERITY_ERROR"),
		"severity.critical":    os.Getenv("DEFENDER_PROXY_SEVERITY_CRITICAL"),
		"history.audit.path":   os.Getenv("DEFENDER_PROXY_HISTORY_AUDIT_PATH"),
		"history.error.enable": os.Getenv("DEFENDER_PROXY_HISTORY_ERROR_ENABLE"),
		"history.error.path":   os.Getenv("DEFENDER_PROXY_HISTORY_ERROR_PATH"),
		"report.api.path":      os.Getenv("DEFENDER_PROXY_REPORT_API_PATH"),
		"report.api.header":    os.Getenv("DEFENDER_PROXY_REPORT_API_HEADER"),
		"report.api.token":     os.Getenv("DEFENDER_PROXY_REPORT_API_TOKEN"),
		"report.auth.username": os.Getenv("DEFENDER_PROXY_REPORT_AUTH_USERNAME"),
		"report.auth.password": os.Getenv("DEFENDER_PROXY_REPORT_AUTH_PASSWORD"),
	}

	BackendVars = DictString{
		"scheme": os.Getenv("DEFENDER_PROXY_BACKEND_SCHEME"),
		"host":   os.Getenv("DEFENDER_PROXY_BACKEND_HOST"),
		"port":   os.Getenv("DEFENDER_PROXY_BACKEND_PORT"),
		"path":   os.Getenv("DEFENDER_PROXY_BACKEND_PATH"),
	}

	exclusionVars = ListString{
		"server.tls.key",
		"server.tls.crt",
		"server.host",
		"server.prefix",

		"security.username",
		"security.password",
		"security.mask.type",
		"security.mask.html",
		"security.mask.json",

		"log.console.type",
		"log.console.separator",
		"log.file.name",
		"log.file.type",
		"log.file.separator",

		"storage.redis.password",

		"proxy.tls.key",
		"proxy.tls.crt",
		"proxy.host",
		"proxy.history.error.path",
		"proxy.report.api.path",
		"proxy.report.api.header",
		"proxy.report.api.token",
		"proxy.report.auth.username",
		"proxy.report.auth.password",

		"backend.path",
	}
)

func CheckEmpty() bool {
	vars := mergeStringMaps(map[string]DictString{
		"app":      AppVars,
		"server":   ServerVars,
		"security": SecurityVars,
		"log":      LogVars,
		"storage":  StorageVars,
		"proxy":    ProxyVars,
		"backend":  BackendVars,
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
