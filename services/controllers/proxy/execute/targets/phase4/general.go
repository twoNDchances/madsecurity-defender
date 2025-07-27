package phase4

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"net/http"
	"strings"
)

func GetBodyData(context *http.Response, targetId uint) (globals.ListString, globals.ListString, globals.DictString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	maps := make(globals.DictString, 0)
	_, data, err := utils.GetResponseBodyContentType(context)
	if err != nil {
		msg := fmt.Sprintf("Target %d: %v", targetId, err)
		errors.WriteErrorTargetLog(msg)
	} else {
		switch d := data.(type) {
		case map[string]interface{}:
			if len(d) > 0 {
				flatMap := make(globals.DictAny, 0)
				utils.FlattenWithValues(d, "", flatMap)
				for key, value := range flatMap {
					keys = append(keys, key)
					values = append(values, fmt.Sprint(value))
					maps[strings.ToLower(key)] = fmt.Sprint(value)
				}
			}
		}
	}
	return keys, values, maps
}
