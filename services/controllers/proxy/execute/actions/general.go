package actions

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func Allow() (bool, bool, bool) {
	return true, true, true
}

func Deny() (bool, bool, bool) {
	return true, false, true
}

func Inspect(context *gin.Context, rule *globals.Rule) (bool, bool, bool) {
	if rule.Severity == nil {
		msg := fmt.Sprintf("Rule %d: missing Severity for Inspect action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	currentlyScore := context.GetInt("current_score")
	switch *rule.Severity {
	case "notice":
		currentlyScore = currentlyScore + globals.ProxyConfigs.Severity.NOTICE
	case "warning":
		currentlyScore = currentlyScore + globals.ProxyConfigs.Severity.WARNING
	case "error":
		currentlyScore = currentlyScore + globals.ProxyConfigs.Severity.ERROR
	case "critical":
		currentlyScore = currentlyScore + globals.ProxyConfigs.Severity.CRITICAL
	}
	context.Set("current_score", currentlyScore)
	return false, true, true
}

func Request(context any, targetPath []globals.Target, target any, rule *globals.Rule) (bool, bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Request action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	options := strings.SplitN(*rule.ActionConfiguration, ",", 2)
	if len(options) != 2 {
		msg := fmt.Sprintf("Rule %d: not enough options for Request action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	methods := globals.ListString{"post", "put", "patch", "delete"}
	if !slices.Contains(methods, options[0]) {
		msg := fmt.Sprintf("Rule %d: Method not in 'get', 'put', 'patch', 'delete' for Request action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	if _, err := url.Parse(options[1]); err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	var targetValues []globals.DictAny
	for _, target := range targetPath {
		targetValues = append(targetValues, globals.DictAny{
			"name": target.Name,
			"alias": target.Alias,
			"type": target.Type,
			"datatype": target.Datatype,
			"engine": target.Engine,
			"engine_configuration": target.EngineConfiguration,
			"final_datatype": target.FinalDatatype,
			"wordlist_id": target.WordlistID,
		})
	}
	body := globals.DictAny{
		"time": time.Now().Format(utils.TimeStampLayout),
		"output": target,
		"target": targetValues,
		"rule": globals.DictAny{
			"name": rule.Name,
			"alias": rule.Alias,
			"comparator": rule.Comparator,
			"inverse": rule.Inverse,
			"value": rule.Value,
			"wordlist_id": rule.WordlistID,
			"action": rule.Action,
			"action_configuration": rule.ActionConfiguration,
			"severity": rule.Severity,
		},
	}
	switch ctx := context.(type) {
	case *gin.Context:
		body["user_agent"] = ctx.Request.UserAgent()
		body["client_ip"] = ctx.ClientIP()
		body["method"] = ctx.Request.Method
		body["path"] = ctx.Request.URL.Path
	case *http.Response:
		body["user_agent"] = ctx.Request.UserAgent()
		body["client_ip"] = ctx.Request.RemoteAddr
		body["method"] = ctx.Request.Method
		body["path"] = ctx.Request.URL.Path
	}
	request, err := utils.NewHttp(options[0], options[1], body)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	go func() {
		response, err := request.Send()
		if err != nil {
			msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
			errors.WriteErrorActionLog(msg)
		} else if response.StatusCode != 200 {
			msg := fmt.Sprintf("Rule %d: Status code %d", rule.ID, response.StatusCode)
			errors.WriteErrorActionLog(msg)
		}
	}()
	return false, true, true
}

func SetScore(context *gin.Context, rule *globals.Rule) (bool, bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Set Score action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	actionConfiguration, err := strconv.Atoi(*rule.ActionConfiguration)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	context.Set("violation_score", actionConfiguration)
	return false, true, true
}

func SetLevel(context *gin.Context, rule *globals.Rule) (bool, bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Set Level action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	actionConfiguration, err := strconv.Atoi(*rule.ActionConfiguration)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	context.Set("violation_level", uint(actionConfiguration))
	return false, true, true
}

func Report(context any, group *globals.Group, targetPath []globals.Target, target any, rule *globals.Rule) (bool, bool, bool) {
	var targetIds globals.ListUint
	for _, target := range targetPath {
		targetIds = append(targetIds, target.ID)
	}
	body := globals.DictAny{
		"auth": globals.DictAny{
			"id": group.DefenderID,
			"username": utils.FallbackWhenEmpty(&globals.SecurityConfigs.Username, nil),
			"password": utils.FallbackWhenEmpty(&globals.SecurityConfigs.Password, nil),
		},
	}
	data := make(globals.DictAny, 0)
	data["time"] = time.Now().Format(utils.TimeStampLayout)
	data["output"] = target
	data["target_ids"] = targetIds
	data["rule_id"] = rule.ID
	switch ctx := context.(type) {
	case *gin.Context:
		data["user_agent"] = ctx.Request.UserAgent()
		data["client_ip"] = ctx.ClientIP()
		data["method"] = ctx.Request.Method
		data["path"] = ctx.Request.URL.Path
	case *http.Response:
		data["user_agent"] = ctx.Request.UserAgent()
		data["client_ip"] = ctx.Request.RemoteAddr
		data["method"] = ctx.Request.Method
		data["path"] = ctx.Request.URL.Path
	}
	body["data"] = data
	managerAddress := fmt.Sprintf("https://%s/api/report/create", globals.SecurityConfigs.ManagerHost)
	request, err := utils.NewHttp("post", managerAddress, body)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	go func() {
		response, err := request.Send()
		if err != nil {
			msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
			errors.WriteErrorActionLog(msg)
		} else if response.StatusCode != 200 {
			msg := fmt.Sprintf("Rule %d: Status code %d", rule.ID, response.StatusCode)
			errors.WriteErrorActionLog(msg)
		}
	}()
	return false, true, true
}

func SetVariable(context *gin.Context, rule *globals.Rule) (bool, bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Set Variable action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	options := strings.SplitN(*rule.ActionConfiguration, ",", 2)
	if len(options) != 2 {
		return true, false, false
	}
	context.Set(options[0], options[1])
	return false, true, true
}

func SetHeader(context any, rule *globals.Rule) (bool, bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Set Header action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	options := strings.SplitN(*rule.ActionConfiguration, ",", 2)
	if len(options) != 2 {
		return true, false, false
	}
	switch ctx := context.(type) {
	case *gin.Context:
		ctx.Request.Header.Set(options[0], options[1])
	case *http.Response:
		ctx.Header.Set(options[0], options[1])
	}
	return false, true, true
}
