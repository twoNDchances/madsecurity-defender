package phase4

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"net/http"
)

func BodyKeys(context *http.Response, target *globals.Target) globals.ListString {
	keys := make(globals.ListString, 0)
	if target.Phase == 4 && target.Alias == "body-keys-response" && target.Name == "keys" && target.Immutable && target.TargetID == nil {
		keys, _, _ = GetBodyData(context, target.ID)
	}
	return keys
}

func BodyValues(context *http.Response, target *globals.Target) globals.ListString {
	values := make(globals.ListString, 0)
	if target.Phase == 4 && target.Alias == "body-values-response" && target.Name == "values" && target.Immutable && target.TargetID == nil {
		_, values, _ = GetBodyData(context, target.ID)
	}
	return values
}

func BodySize(context *http.Response, target *globals.Target) float64 {
	var size float64
	if target.Phase == 4 && target.Alias == "body-size-response" && target.Name == "size" && target.Immutable && target.TargetID == nil {
		keys, _, _ := GetBodyData(context, target.ID)
		size = float64(len(keys))
	}
	return size
}

func BodyLength(context *http.Response, target *globals.Target) float64 {
	var length float64
	if target.Phase == 4 && target.Alias == "body-length-response" && target.Name == "length" && target.Immutable && target.TargetID == nil {
		length = float64(context.ContentLength)
	}
	return length
}

func FullBody(context *http.Response, target *globals.Target) string {
	var raw string
	if target.Phase == 4 && target.Alias == "full-body-response" && target.Name == "raw" && target.Immutable && target.TargetID == nil {
		data, err := utils.DecodeResponseBody(context)
		if err != nil {
			msg := fmt.Sprintf("Target %d: %v", target.ID, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			raw = string(data)
		}
	}
	return raw
}
