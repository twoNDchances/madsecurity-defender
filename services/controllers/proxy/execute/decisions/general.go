package decisions

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
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
	return false, true, true, true
}

func Bait(context *http.Response, contextGin *gin.Context, decision *globals.Decision) (bool, bool, bool, bool) {
	if decision.PhaseType != "response" || contextGin.GetInt("current_score") < decision.Score {
		return false, true, false, true
	}
	return false, true, true, true
}
