package phase2

import (
	"bytes"
	"fmt"
	"io"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"

	"github.com/gin-gonic/gin"
)

func BodyKeys(context *gin.Context, target *globals.Target) globals.ListString {
	keys := make(globals.ListString, 0)
	if target.Phase == 2 && target.Alias == "body-keys-request" && target.Name == "keys" && target.Immutable && target.TargetID == nil {
		keys, _, _ = GetBodyData(context, target.ID)
	}
	return keys
}

func FileKeys(context *gin.Context, target *globals.Target) globals.ListString {
	keys := make(globals.ListString, 0)
	if target.Phase == 2 && target.Alias == "file-keys-request" && target.Name == "keys" && target.Immutable && target.TargetID == nil {
		keys, _, _, _, _, _ = GetFileData(context, target.ID)
	}
	return keys
}

func BodyValues(context *gin.Context, target *globals.Target) globals.ListString {
	values := make(globals.ListString, 0)
	if target.Phase == 2 && target.Alias == "body-values-request" && target.Name == "values" && target.Immutable && target.TargetID == nil {
		_, values, _ = GetBodyData(context, target.ID)
	}
	return values
}

func FileValues(context *gin.Context, target *globals.Target) globals.ListString {
	values := make(globals.ListString, 0)
	if target.Phase == 2 && target.Alias == "file-values-request" && target.Name == "values" && target.Immutable && target.TargetID == nil {
		_, values, _, _, _, _ = GetFileData(context, target.ID)
	}
	return values
}

func FileNames(context *gin.Context, target *globals.Target) globals.ListString {
	names := make(globals.ListString, 0)
	if target.Phase == 2 && target.Alias == "file-names-request" && target.Name == "names" && target.Immutable && target.TargetID == nil {
		_, _, _, names, _, _ = GetFileData(context, target.ID)
	}
	return names
}

func FileExtensions(context *gin.Context, target *globals.Target) globals.ListString {
	extensions := make(globals.ListString, 0)
	if target.Phase == 2 && target.Alias == "file-extensions-request" && target.Name == "extensions" && target.Immutable && target.TargetID == nil {
		_, _, _, _, extensions, _ = GetFileData(context, target.ID)
	}
	return extensions
}

func BodySize(context *gin.Context, target *globals.Target) float64 {
	var size float64
	if target.Phase == 2 && target.Alias == "body-size-request" && target.Name == "size" && target.Immutable && target.TargetID == nil {
		keys, _, _ := GetBodyData(context, target.ID)
		size = float64(len(keys))
	}
	return size
}

func FileSize(context *gin.Context, target *globals.Target) float64 {
	var size float64
	if target.Phase == 2 && target.Alias == "file-size-request" && target.Name == "size" && target.Immutable && target.TargetID == nil {
		keys, _, _, _, _, _ := GetFileData(context, target.ID)
		size = float64(len(keys))
	}
	return size
}

func FileNameSize(context *gin.Context, target *globals.Target) float64 {
	var nameSize float64
	if target.Phase == 2 && target.Alias == "file-name-size-request" && target.Name == "name-size" && target.Immutable && target.TargetID == nil {
		_, _, _, names, _, _ := GetFileData(context, target.ID)
		nameSize = float64(len(names))
	}
	return nameSize
}

func BodyLength(context *gin.Context, target *globals.Target) float64 {
	var length float64
	if target.Phase == 2 && target.Alias == "body-length-request" && target.Name == "length" && target.Immutable && target.TargetID == nil {
		_, _, maps := GetBodyData(context, target.ID)
		for key, value := range maps {
			mapLength := float64(len(key) + len(value))
			length += mapLength
		}
	}
	return length
}

func FileLength(context *gin.Context, target *globals.Target) float64 {
	var length float64
	if target.Phase == 2 && target.Alias == "file-length-request" && target.Name == "length" && target.Immutable && target.TargetID == nil {
		_, _, _, _, _, mapLength := GetFileData(context, target.ID)
		for _, fileLength := range mapLength {
			length += fileLength
		}
	}
	return length
}

func FullBody(context *gin.Context, target *globals.Target) string {
	var raw string
	if target.Phase == 2 && target.Alias == "full-body-request" && target.Name == "raw" && target.Immutable && target.TargetID == nil {
		bodyBytes, err := io.ReadAll(context.Request.Body)
		if err != nil {
			msg := fmt.Sprintf("Target %d: %v", target.ID, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			context.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			raw = string(bodyBytes)
		}
	}
	return raw
}
