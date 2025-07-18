package phase2

import (
	"bytes"
	"fmt"
	"io"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h2non/filetype"
)

func extractApplication(context *gin.Context, targetId uint) (globals.ListString, globals.ListString, globals.DictString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	maps := make(globals.DictString, 0)
	var (
		data interface{}
		err  error
	)
	switch context.ContentType() {
	case "application/json":
		err = context.ShouldBindBodyWithJSON(&data)
	case "application/xml", "text/xml":
		err = context.ShouldBindBodyWithXML(&data)
	case "application/yaml":
		err = context.ShouldBindBodyWithYAML(&data)
	}
	if err != nil {
		msg := fmt.Sprintf("Target %d: %v", targetId, err)
		errors.WriteErrorTargetLog(msg)
	} else {
		flatMap := make(globals.DictAny, 0)
		utils.FlattenWithValues(data, "", flatMap)
		for key, value := range flatMap {
			keys = append(keys, key)
			values = append(values, fmt.Sprint(value))
			maps[strings.ToLower(key)] = fmt.Sprint(value)
		}
	}
	return keys, values, maps
}

func extractApplicationXWwwFormUrlEncoded(context *gin.Context, targetId uint) (globals.ListString, globals.ListString, globals.DictString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	maps := make(globals.DictString, 0)
	if err := context.Request.ParseForm(); err != nil {
		msg := fmt.Sprintf("Target %d: %v", targetId, err)
		errors.WriteErrorTargetLog(msg)
	} else {
		for key, value := range context.Request.PostForm {
			keys = append(keys, key)
			values = append(values, value...)
			maps[strings.ToLower(key)] = strings.Join(value, ",")
		}
	}
	return keys, values, maps
}

func extractMultipartBodyFormData(context *gin.Context, targetId uint) (globals.ListString, globals.ListString, globals.DictString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	maps := make(globals.DictString, 0)
	contentLength := context.Request.ContentLength
	if contentLength > 0 {
		if err := context.Request.ParseMultipartForm(contentLength); err != nil {
			msg := fmt.Sprintf("Target %d: %v", targetId, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			for key, value := range context.Request.MultipartForm.Value {
				keys = append(keys, key)
				values = append(values, value...)
				maps[strings.ToLower(key)] = strings.Join(value, ",")
			}
		}
	}
	return keys, values, maps
}

func GetBodyData(context *gin.Context, targetId uint) (globals.ListString, globals.ListString, globals.DictString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	maps := make(globals.DictString, 0)
	contentType := strings.ToLower(context.ContentType())
	if len(contentType) > 0 {
		bodyBytes, err := io.ReadAll(context.Request.Body)
		if err != nil {
			msg := fmt.Sprintf("Target %d: %v", targetId, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			context.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			switch contentType {
			case "application/json", "application/xml", "text/xml", "application/yaml":
				jsonKeys, jsonValues, json := extractApplication(context, targetId)
				keys = append(keys, jsonKeys...)
				values = append(values, jsonValues...)
				maps = json
			case "application/x-www-form-urlencoded":
				urlKeys, urlValues, json := extractApplicationXWwwFormUrlEncoded(context, targetId)
				keys = append(keys, urlKeys...)
				values = append(values, urlValues...)
				maps = json
			case "multipart/form-data":
				formKeys, formValues, json := extractMultipartBodyFormData(context, targetId)
				keys = append(keys, formKeys...)
				values = append(values, formValues...)
				maps = json
			}
			context.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}
	return keys, values, maps
}

func extractMultipartFileFormData(context *gin.Context, targetId uint) (globals.ListString, globals.ListString, globals.DictString, globals.ListString, globals.ListString, []float64) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	maps := make(globals.DictString, 0)
	names := make(globals.ListString, 0)
	extensions := make(globals.ListString, 0)
	lengths := make([]float64, 0)
	contentLength := context.Request.ContentLength
	if contentLength > 0 {
		bodyBytes, err := io.ReadAll(context.Request.Body)
		if err != nil {
			msg := fmt.Sprintf("Target %d: %v", targetId, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			context.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			if err := context.Request.ParseMultipartForm(contentLength); err != nil {
				msg := fmt.Sprintf("Target %d: %v", targetId, err)
				errors.WriteErrorTargetLog(msg)
			} else {
				for key, value := range context.Request.MultipartForm.File {
					keys = append(keys, key)
					for _, fileHeader := range value {
						names = append(names, fileHeader.Filename)
						lengths = append(lengths, float64(fileHeader.Size))
						file, err := fileHeader.Open()
						if err != nil {
							msg := fmt.Sprintf("Target %d: %v", targetId, err)
							errors.WriteErrorTargetLog(msg)
							continue
						}
						defer file.Close()
						contentBytes, err := io.ReadAll(file)
						if err != nil {
							msg := fmt.Sprintf("Target %d: %v", targetId, err)
							errors.WriteErrorTargetLog(msg)
							continue
						}
						values = append(values, string(contentBytes))
						maps[strings.ToLower(key)] = string(contentBytes)
						headSize := min(len(contentBytes), 261)
						head := contentBytes[:headSize]
						kind, err := filetype.Match(head)
						var extension string
						if err != nil || kind == filetype.Unknown || kind.Extension == "" {
							ext := filepath.Ext(fileHeader.Filename)
							extension = strings.TrimPrefix(ext, ".")
						} else {
							extension = kind.Extension
						}
						extensions = append(extensions, extension)
					}
				}
			}
			context.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}
	return keys, values, maps, names, extensions, lengths
}

func GetFileData(context *gin.Context, targetId uint) (globals.ListString, globals.ListString, globals.DictString, globals.ListString, globals.ListString, []float64) {
	return extractMultipartFileFormData(context, targetId)
}
