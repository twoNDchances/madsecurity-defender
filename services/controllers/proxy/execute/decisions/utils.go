package decisions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/clbanning/mxj/v2"
	"github.com/tidwall/sjson"
	"gopkg.in/yaml.v3"
)

type valueConfig struct {
	kind  string
	aim   string
	value string
}

func getValueConfig(decisionWordlistId uint) *[]valueConfig {
	valueConfigs := make([]valueConfig, 0)
	for _, word := range globals.Words {
		if word.WordlistID != decisionWordlistId {
			continue
		}
		configs := strings.SplitN(word.Content, "@>", 3)
		if len(configs) != 3 {
			continue
		}
		valueConfigs = append(valueConfigs, valueConfig{
			kind:  configs[0],
			aim:   configs[1],
			value: configs[2],
		})
	}
	return &valueConfigs
}

func assignValueToResponseBody(context *http.Response, decision *globals.Decision) error {
	if decision.WordlistID == nil {
		msg := fmt.Sprintf("Decision %d: missing Wordlist ID for Tag action", decision.ID)
		return utils.ToError(msg)
	}
	kind, data, err := utils.GetResponseBodyContentType(context)
	if err != nil {
		return err
	}
	valueConfigs := getValueConfig(*decision.WordlistID)
	switch kind {
	case "json", "xml", "yaml":
		switch d := data.(type) {
		case map[string]interface{}:
			jsonBytes, err := json.Marshal(d)
			if err != nil {
				return err
			}
			jsonString := string(jsonBytes)
			for _, config := range *valueConfigs {
				if (kind == "json" && config.kind == "json") || (kind == "xml" && config.kind == "xml") || (kind == "yaml" && config.kind == "yaml") {
					jsonString, err = sjson.Set(jsonString, config.aim, config.value)
				}
				if err != nil {
					return err
				}
			}
			backbone := make(globals.DictAny, 0)
			if err := json.Unmarshal([]byte(jsonString), &backbone); err != nil {
				return err
			}
			switch kind {
			case "xml":
			    mv := mxj.Map(backbone)
				xmlBytes, err := mv.Xml()
				if  err != nil {
					return err
				}
				jsonString = string(xmlBytes)
			case "yaml":
				yamlBytes, err := yaml.Marshal(backbone)
				if err != nil {
					return err
				}
				jsonString = string(yamlBytes)
			}
			context.ContentLength = int64(len(jsonString))
			context.Body = io.NopCloser(bytes.NewReader([]byte(jsonString)))
		}
	case "html":
		switch d := data.(type) {
		case string:
			reader := strings.NewReader(d)
			document, err := goquery.NewDocumentFromReader(reader)
			if err != nil {
				fmt.Println(err)
				return err
			}
			for _, config := range *valueConfigs {
				if kind == "html" && config.kind == "html" {
					document.Find(config.aim).AppendHtml(config.value)
				}
			}
			htmlString, err := document.Html()
			if err != nil {
				fmt.Println(err)
				return err
			}
			context.ContentLength = int64(len(htmlString))
			context.Body = io.NopCloser(bytes.NewReader([]byte(htmlString)))
		}
	}
	// if err := utils.EncodeResponseBody(context); err != nil {
	// 	fmt.Println(err)
	// 	return err
	// }
	bodyBytes, _ := io.ReadAll(context.Body)
	bodyEncoded, err := utils.EncodeResponseBody(bodyBytes, context.Header.Get("Content-Encoding"))
	if err != nil {
		return err
	}
	fmt.Println(string(bodyEncoded))
	context.Body = io.NopCloser(bytes.NewReader(bodyEncoded))
	return nil
}
