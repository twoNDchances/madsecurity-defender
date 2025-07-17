package phase4

import (
	"encoding/json"
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/basgys/goxml2json"
	"gopkg.in/yaml.v3"
)

func GetBodyData(context *http.Response, targetId uint) (globals.ListString, globals.ListString, globals.DictString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	maps := make(globals.DictString, 0)
	contentType := context.Header.Get("Content-Type")
	if len(contentType) > 0 {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			msg := fmt.Sprintf("Target %d: %v", targetId, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			formatRegex := regexp.MustCompile(`(?i)\b(json|xml|yaml)\b`)
			match := formatRegex.FindStringSubmatch(mediaType)
			if len(match) >= 2 {
				bodyBytes, err := utils.DecodeResponseBody(context)
				if err != nil {
					msg := fmt.Sprintf("Target %d: %v", targetId, err)
					errors.WriteErrorTargetLog(msg)
				} else {
					data := make(map[string]interface{}, 0)
					switch strings.ToLower(match[1]) {
					case "json":
						if err := json.Unmarshal(bodyBytes, &data); err != nil {
							msg := fmt.Sprintf("Target %d: %v", targetId, err)
							errors.WriteErrorTargetLog(msg)
						}
					case "xml":
						xmlReader := strings.NewReader(string(bodyBytes))
						jsonReader, err := xml2json.Convert(xmlReader)
						if err != nil {
							msg := fmt.Sprintf("Target %d: %v", targetId, err)
							errors.WriteErrorTargetLog(msg)
						} else if err := json.Unmarshal(jsonReader.Bytes(), &data); err != nil {
							msg := fmt.Sprintf("Target %d: %v", targetId, err)
							errors.WriteErrorTargetLog(msg)
						}
					case "yaml":
						err := yaml.Unmarshal(bodyBytes, &data)
						if err != nil {
							msg := fmt.Sprintf("Target %d: %v", targetId, err)
							errors.WriteErrorTargetLog(msg)
						}
					}
					if len(data) > 0 {
						flatMap := make(globals.DictAny, 0)
						utils.FlattenWithValues(data, "", flatMap)
						for key, value := range flatMap {
							keys = append(keys, key)
							values = append(values, fmt.Sprint(value))
							maps[strings.ToLower(key)] = fmt.Sprint(value)
						}
					}
				}
			}
		}
	}
	return keys, values, maps
}
