package decisions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/clbanning/mxj/v2"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/sjson"
	"gopkg.in/yaml.v3"
)

func Deny(context *gin.Context, decision *globals.Decision) (bool, bool, bool, bool) {
	if context.GetInt("current_score") < decision.Score {
		return false, true, false, true
	}
	return true, false, true, true
}

func Redirect(context *gin.Context, decision *globals.Decision) (bool, bool, bool, bool) {
	if decision.PhaseType != "request" || context.GetInt("current_score") < decision.Score {
		return false, true, false, true
	}
	if decision.ActionConfiguration == nil {
		msg := fmt.Sprintf("Decision %d: missing Action Configuration for Redirect action", decision.ID)
		errors.WriteErrorDecisionLog(msg)
		return true, false, false, true
	}
	remote, err := url.Parse(*decision.ActionConfiguration)
	if err != nil {
		msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
		errors.WriteErrorDecisionLog(msg)
		return true, false, false, true
	}
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Director = func(request *http.Request) {
		request.URL.Scheme = remote.Scheme
		request.URL.Host = remote.Host
		request.URL.Path = fmt.Sprintf("%s%s", globals.BackendConfigs.Path, context.Param("backendPath"))
		request.Host = remote.Host
		request.Header = context.Request.Header.Clone()
	}
	proxy.ServeHTTP(context.Writer, context.Request)
	return true, false, true, false
}

func Kill(context *gin.Context, decision *globals.Decision) (bool, bool, bool, bool) {
	if decision.PhaseType != "request" || context.GetInt("current_score") < decision.Score {
		return false, true, false, true
	}
	if decision.ActionConfiguration == nil {
		msg := fmt.Sprintf("Decision %d: missing Action Configuration for Kill action", decision.ID)
		errors.WriteErrorDecisionLog(msg)
		return true, false, false, true
	}
	options := strings.SplitN(*decision.ActionConfiguration, ",", 2)
	if len(options) != 2 {
		msg := fmt.Sprintf("Decision %d: not enough options for Kill action", decision.ID)
		errors.WriteErrorDecisionLog(msg)
		return true, false, false, true
	}
	request, err := utils.NewHttp(
		"post",
		fmt.Sprintf("%s%s", globals.BackendConfigs.BuildUrl(), options[1]),
		"",
		"",
		globals.DictString{},
		map[string]any{
			"header": options[0],
		},
	)
	if err != nil {
		msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false, false, true
	}
	go func() {
		response, err := request.Send()
		if err != nil {
			msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
			errors.WriteErrorActionLog(msg)
		} else if response.StatusCode != 200 {
			msg := fmt.Sprintf("Decision %d: Status code %d", decision.ID, response.StatusCode)
			errors.WriteErrorActionLog(msg)
		}
	}()
	return true, false, true, true
}

func Tag(context *gin.Context, decision *globals.Decision) (bool, bool, bool, bool) {
	if decision.PhaseType != "request" || context.GetInt("current_score") < decision.Score {
		return false, true, false, true
	}
	if decision.WordlistID == nil {
		msg := fmt.Sprintf("Decision %d: missing Wordlist ID for Tag action", decision.ID)
		errors.WriteErrorDecisionLog(msg)
		return true, false, false, true
	}
	headers := make(globals.DictString, 0)
	for _, word := range globals.Words {
		if word.WordlistID == *decision.WordlistID {
			header := strings.SplitN(word.Content, "=", 2)
			if len(header) != 2 {
				msg := fmt.Sprintf("Decision %d: not enough options for Tag action", decision.ID)
				errors.WriteErrorDecisionLog(msg)
				continue
			}
			headers[header[0]] = header[1]
		}
	}
	for key, value := range headers {
		context.Request.Header.Set(key, value)
	}
	return false, true, true, true
}

func Warn(context *http.Response, contextGin *gin.Context, decision *globals.Decision) (bool, bool, bool, bool) {
	if decision.PhaseType != "response" || contextGin.GetInt("current_score") < decision.Score {
		return false, true, false, true
	}
	if context.StatusCode == 302 {
		return false, true, false, true
	}
	if decision.WordlistID == nil {
		msg := fmt.Sprintf("Decision %d: missing Wordlist ID for Warn action", decision.ID)
		errors.WriteErrorDecisionLog(msg)
		return true, false, false, true
	}
	aimConfigs := make([]globals.DictString, 0)
	for _, word := range globals.Words {
		if word.WordlistID != *decision.WordlistID {
			continue
		}
		configs := strings.SplitN(word.Content, "@>", 3)
		if len(configs) != 3 {
			continue
		}
		aimConfigs = append(aimConfigs, globals.DictString{
			"type": configs[0],
			"aim": configs[1],
			"value": configs[2],
		})
	}
	for _, config := range aimConfigs {
		if config["type"] != "header" {
			continue
		}
		context.Header.Set(config["aim"], config["value"])
	}
	kind, data, err := utils.GetResponseBodyContentType(context)
	if err != nil {
		msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
		errors.WriteErrorDecisionLog(msg)
		return true, false, false, true
	}
	if kind == "" {
		return false, true, false, true
	}
	switch kind {
	case "json", "xml", "yaml":
		switch d := data.(type) {
		case map[string]interface{}:
			jsonBytes, err := json.Marshal(d)
			if err != nil {
				msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
				errors.WriteErrorDecisionLog(msg)
				return true, false, false, true
			}
			jsonString := string(jsonBytes)
			for _, config := range aimConfigs {
				if (kind == "json" && config["type"] == "json") || (kind == "xml" && config["type"] == "xml") || (kind == "yaml" && config["type"] == "yaml") {
					jsonString, err = sjson.Set(jsonString, config["aim"], config["value"])
					if err != nil {
						msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
						errors.WriteErrorDecisionLog(msg)
						return true, false, false, true
					}
				}
			}
			backbone := make(globals.DictAny, 0)
			if err := json.Unmarshal([]byte(jsonString), &backbone); err != nil {
				msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
				errors.WriteErrorDecisionLog(msg)
				return true, false, false, true
			}
			switch kind {
			case "xml":
			    mv := mxj.Map(backbone)
				xmlBytes, err := mv.Xml()
				if  err != nil {
					msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
					errors.WriteErrorDecisionLog(msg)
					return true, false, false, true
				}
				jsonString = string(xmlBytes)
			case "yaml":
				yamlBytes, err := yaml.Marshal(backbone)
				if err != nil {
					msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
					errors.WriteErrorDecisionLog(msg)
					return true, false, false, true
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
				msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
				errors.WriteErrorDecisionLog(msg)
				return true, false, false, true
			}
			for _, config := range aimConfigs {
				if kind == "html" && config["type"] == "html" {
					document.Find(config["aim"]).AppendHtml(config["value"])
				}
			}
			htmlString, err := document.Html()
			if err != nil {
				msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
				errors.WriteErrorDecisionLog(msg)
				return true, false, false, true
			}
			context.ContentLength = int64(len(htmlString))
			context.Body = io.NopCloser(bytes.NewReader([]byte(htmlString)))
		}
	}
	if err:= utils.EncodeResponseBody(context); err != nil {
		msg := fmt.Sprintf("Decision %d: %v", decision.ID, err)
		errors.WriteErrorDecisionLog(msg)
		return true, false, false, true
	}
	return false, true, true, true
}
