package phase3

import (
	"fmt"
	"madsecurity-defender/globals"
	"net/http"
	"strings"
)

func HeaderKeys(context *http.Response, target *globals.Target) globals.ListString {
	var keys globals.ListString
	if target.Phase == 3 && target.Alias == "header-keys-response" && target.Name == "keys" && target.Immutable && target.TargetID == nil {
		headers := GetHeaderData(context)
		for key := range headers {
			keys = append(keys, strings.ToLower(key))
		}
	}
	return keys
}

func HeaderValues(context *http.Response, target *globals.Target) globals.ListString {
	var values globals.ListString
	if target.Phase == 3 && target.Alias == "header-values-response" && target.Name == "values" && target.Immutable && target.TargetID == nil {
		headers := GetHeaderData(context)
		for _, value := range headers {
			values = append(values, value...)
		}
	}
	return values
}

func HeaderSize(context *http.Response, target *globals.Target) float64 {
	var size float64
	if target.Phase == 3 && target.Alias == "header-size-response" && target.Name == "size" && target.Immutable && target.TargetID == nil {
		size = float64(len(GetHeaderData(context)))
	}
	return size
}

func ServerStatus(context *http.Response, target *globals.Target) float64 {
	var status float64
	if target.Phase == 3 && target.Alias == "server-status" && target.Name == "status" && target.Immutable && target.TargetID == nil {
		status = float64(context.Request.Response.StatusCode)
	}
	return status
}

func ServerProtocol(context *http.Response, target *globals.Target) string {
	var protocol string
	if target.Phase == 3 && target.Alias == "server-protocol" && target.Name == "protocol" && target.Immutable && target.TargetID == nil {
		protocol = context.Proto
	}
	return protocol
}

func FullHeader(context *http.Response, target *globals.Target) string {
	var raw strings.Builder
	if target.Phase == 3 && target.Alias == "full-header-response" && target.Name == "raw" && target.Immutable && target.TargetID == nil {
		for key, value := range GetHeaderData(context) {
			raw.WriteString(fmt.Sprintf("%s: %s\n", key, strings.Join(value, ",")))
		}
	}
	return raw.String()
}
