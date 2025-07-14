package actions

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
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
	var currentlyScore int
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

func Request(context *gin.Context, targetPath []globals.Target, target any, rule *globals.Rule) (bool, bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Request action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false, false
	}
	options := strings.SplitN(*rule.ActionConfiguration, ",", 2)
	if len(options) != 2 {
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
		"user_agent": context.Request.UserAgent(),
		"client_ip": context.RemoteIP(),
		"method": context.Request.Method,
		"path": context.Request.URL.Path,
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

func Report(context *gin.Context, group *globals.Group, targetPath []globals.Target, target any, rule *globals.Rule) (bool, bool, bool) {
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
		"data": globals.DictAny{
			"time": time.Now().Format(utils.TimeStampLayout),
			"output": target,
			"user_agent": context.Request.UserAgent(),
			"client_ip": context.RemoteIP(),
			"method": context.Request.Method,
			"path": context.Request.URL.Path,
			"target_ids": targetIds,
			"rule_id": rule.ID,
		},
	}
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
	options := strings.SplitN(*rule.ActionConfiguration, ",", 2)
	if len(options) != 2 {
		return true, false, false
	}
	context.Set(options[0], options[1])
	return false, true, true
}
