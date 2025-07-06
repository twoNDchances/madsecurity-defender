package phase2

import (
	"madsecurity-defender/globals"
	"strings"

	"github.com/gin-gonic/gin"
)

func BodyKeys(context *gin.Context, target *globals.Target) globals.ListString {
	keys := make(globals.ListString, 0)
	if target.Phase == 2 && target.Alias == "body-keys" && target.Name == "keys" && target.Immutable && target.TargetID == nil {
		if len(context.ContentType()) > 0 {
			contentType := strings.ToLower(context.ContentType())
			switch contentType {
			case "application/json":
				jsonKeys, _ := extractApplicationJson(context, target.ID)
				keys = append(keys, jsonKeys...)
			case "application/x-www-form-urlencoded":
				urlKeys, _ := extractApplicationXWwwFormUrlEncoded(context, target.ID)
				keys = append(keys, urlKeys...)
			case "multipart/form-data":
				formKeys, _ := extractMultipartBodyFormData(context, target.ID)
				keys = append(keys, formKeys...)
			}
		}
	}
	return keys
}

func BodyValues(context *gin.Context, target *globals.Target) globals.ListString {
	values := make(globals.ListString, 0)
	if target.Phase == 2 && target.Alias == "body-values" && target.Name == "values" && target.Immutable && target.TargetID == nil {
		if len(context.ContentType()) > 0 {
			contentType := strings.ToLower(context.ContentType())
			switch contentType {
			case "application/json":
				_, jsonValues := extractApplicationJson(context, target.ID)
				values = append(values, jsonValues...)
			case "application/x-www-form-urlencoded":
				_, urlValues := extractApplicationXWwwFormUrlEncoded(context, target.ID)
				values = append(values, urlValues...)
			case "multipart/form-data":
				_, formValues := extractMultipartBodyFormData(context, target.ID)
				values = append(values, formValues...)
			}
		}
	}
	return values
}


