package middlewares

import (
	"fmt"
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
	"os"

	"github.com/gin-gonic/gin"
)

func Log() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(parameters gin.LogFormatterParams) string {
		logDefaultFormat := func(separator string) string {
			return fmt.Sprintf(
				"%s %s %d %s %s %s %s %s %s %s %s %s %d %s %d %s %s\n",
				parameters.TimeStamp.Format(utils.TimeStampLayout),
				separator,
				parameters.StatusCode,
				separator,
				parameters.Request.UserAgent(),
				separator,
				parameters.ClientIP,
				separator,
				parameters.Method,
				separator,
				parameters.Path,
				separator,
				parameters.Request.ContentLength,
				separator,
				parameters.BodySize,
				separator,
				utils.ReplaceIfWhiteSpace(parameters.ErrorMessage, "-"),
			)
		}
		logJsonFormat := func(eachField, lastField string) string {
			return fmt.Sprintf(
				`{%s"time": "%s",%s"status": %d,%s"client_ip": "%s",%s"user_agent": "%s",%s"method": "%s",%s"path": "%s",%s"request_length": %d,%s"response_length": %d,%s"error": "%s"%s}`,
				eachField,
				parameters.TimeStamp.Format(utils.TimeStampLayout),
				eachField,
				parameters.StatusCode,
				eachField,
				parameters.ClientIP,
				eachField,
				parameters.Request.UserAgent(),
				eachField,
				parameters.Method,
				eachField,
				parameters.Path,
				eachField,
				parameters.Request.ContentLength,
				eachField,
				parameters.BodySize,
				eachField,
				utils.ReplaceIfWhiteSpace(parameters.ErrorMessage, "-"),
				lastField,
			) + "\n"
		}
		if globals.LogConfigs.File.Enable {
			file, err := os.OpenFile(globals.LogConfigs.File.Name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Println(utils.NewServerError("Log.File.Name", err.Error()))
			} else {
				if globals.LogConfigs.File.Type == "json" {
					file.WriteString(logJsonFormat("", ""))
				} else {
					file.WriteString(logDefaultFormat(globals.LogConfigs.File.Separator))
				}
			}
		}
		if globals.LogConfigs.Console.Enable {
			if globals.LogConfigs.Console.Type == "json" {
				return logJsonFormat("\n    ", "\n")
			}
			return logDefaultFormat(globals.LogConfigs.Console.Separator)
		}
		return ""
	})
}
