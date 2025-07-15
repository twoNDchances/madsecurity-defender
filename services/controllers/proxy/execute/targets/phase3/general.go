package phase3

import "net/http"

func GetHeaderData(context *http.Response) map[string][]string {
	return context.Header
}
