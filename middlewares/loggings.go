package middlewares

import (
	"fmt"
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
	"os"

	"github.com/gin-gonic/gin"
)

const timeStampLayout = "15:04:05 - 02/01/2006"

func Log(logging *globals.Log) gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(parameters gin.LogFormatterParams) string {
		logDefaultFormat := func(separator string) string {
			return fmt.Sprintf(
				"%s %s %d %s %s %s %s %s %s %s %s %s %d %s %d %s %s\n",
				parameters.TimeStamp.Format(timeStampLayout),
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
		logJsonFormat := func() string {
			return fmt.Sprintf(
				`{
	"time": "%s",
	"status": %d,
	"client_ip": "%s",
	"user_agent": "%s",
	"method": "%s",
	"path": "%s",
	"request_length": %d,
	"response_length": %d,
	"error": "%s"
}`,
				parameters.TimeStamp.Format(timeStampLayout),
				parameters.StatusCode,
				parameters.ClientIP,
				parameters.Request.UserAgent(),
				parameters.Method,
				parameters.Path,
				parameters.Request.ContentLength,
				parameters.BodySize,
				utils.ReplaceIfWhiteSpace(parameters.ErrorMessage, "-"),
			) + "\n"
		}
		if logging.File.Enable {
			file, err := os.OpenFile(logging.File.Name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Println(utils.NewProxyError("Log.File.Name", err.Error()))
			} else {
				if logging.File.Type == "json" {
					file.WriteString(logJsonFormat())
				} else {
					file.WriteString(logDefaultFormat(logging.File.Separator))
				}
			}
		}
		if logging.Console.Enable {
			if logging.Console.Type == "json" {
				return logJsonFormat()
			}
			return logDefaultFormat(logging.Console.Separator)
		}
		return ""
	})
}
