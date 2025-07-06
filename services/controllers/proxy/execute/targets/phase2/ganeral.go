package phase2

import (
	"fmt"
	"io"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"strconv"

	"github.com/gin-gonic/gin"
)

func flattenWithValues(data interface{}, prefix string, out globals.DictAny) {
    switch v := data.(type) {
    case globals.DictAny:
        for key, val := range v {
            fullKey := key
            if prefix != "" {
                fullKey = prefix + "." + key
            }
            flattenWithValues(val, fullKey, out)
        }
    case []interface{}:
        for i, val := range v {
            fullKey := prefix + "." + strconv.Itoa(i)
            flattenWithValues(val, fullKey, out)
        }
    default:
        out[prefix] = v
    }
}

func extractApplicationJson(context *gin.Context, targetId uint) (globals.ListString, globals.ListString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	var data interface{}
	if err := context.ShouldBindBodyWithJSON(&data); err != nil {
		msg := fmt.Sprintf("Target %d: %v", targetId, err)
		errors.WriteErrorTargetLog(msg)
    } else {
		flatMap := make(globals.DictAny, 0)
		flattenWithValues(data, "", flatMap)
		for key, value := range flatMap {
			keys = append(keys, key)
			values = append(values, fmt.Sprint(value))
		}
	}
	return keys, values
}

func extractApplicationXWwwFormUrlEncoded(context *gin.Context, targetId uint) (globals.ListString, globals.ListString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	if err := context.Request.ParseForm(); err != nil {
		msg := fmt.Sprintf("Target %d: %v", targetId, err)
		errors.WriteErrorTargetLog(msg)
	} else {
		for key, value := range context.Request.PostForm {
			keys = append(keys, key)
			values = append(values, value...)
		}
	}
	return keys, values
}

func extractMultipartBodyFormData(context *gin.Context, targetId uint) (globals.ListString, globals.ListString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	contentLength := context.Request.ContentLength
	if contentLength > 0 {
		if err := context.Request.ParseMultipartForm(contentLength); err != nil {
			msg := fmt.Sprintf("Target %d: %v", targetId, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			for key, value := range context.Request.MultipartForm.Value {
				keys = append(keys, key)
				values = append(values, value...)
			}
		}
	}
	return keys, values
}

func extractMultipartFileFormData(context *gin.Context, targetId uint) (globals.ListString, globals.ListString, globals.ListString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	names := make(globals.ListString, 0)
	contentLength := context.Request.ContentLength
	if contentLength > 0 {
		if err := context.Request.ParseMultipartForm(contentLength); err != nil {
			msg := fmt.Sprintf("Target %d: %v", targetId, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			for key, value := range context.Request.MultipartForm.File {
				keys = append(keys, key)
				for _, fileHeader := range value {
					names = append(names, fileHeader.Filename)
					file, err := fileHeader.Open()
					if err != nil {
						msg := fmt.Sprintf("Target %d: %v", targetId, err)
						errors.WriteErrorTargetLog(msg)
						continue
					}
					contentBytes, err := io.ReadAll(file)
					if err != nil {
						msg := fmt.Sprintf("Target %d: %v", targetId, err)
						errors.WriteErrorTargetLog(msg)
						continue
					}
					values = append(values, string(contentBytes))
				}
			}
		}
	}
	return keys, values, names
}
