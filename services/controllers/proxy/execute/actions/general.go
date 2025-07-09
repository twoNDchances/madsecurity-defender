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

	"github.com/gin-gonic/gin"
)

func Allow() (bool, bool) {
	return true, true
}

func Deny() (bool, bool) {
	return true, false
}

func Inspect(context *gin.Context, rule *globals.Rule) (bool, bool) {
	if rule.Severity == nil {
		msg := fmt.Sprintf("Rule %d: missing Severity for Inspect action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false
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
	return false, true
}

func Request(target any, rule *globals.Rule) (bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Request action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	options := strings.SplitN(*rule.ActionConfiguration, ",", 2)
	if len(options) != 2 {
		return true, false
	}
	methods := globals.ListString{"post", "put", "patch", "delete"}
	if !slices.Contains(methods, options[0]) {
		msg := fmt.Sprintf("Rule %d: Method not in 'get', 'put', 'patch', 'delete' for Request action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	if _, err := url.Parse(options[1]); err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	body := globals.DictAny{
		// ""
	}
	request, err := utils.NewHttp(options[0], options[1], body)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	response, err := request.Send()
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	if response.StatusCode != 200 {
		msg := fmt.Sprintf("Rule %d: Status code %d", rule.ID, response.StatusCode)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	return false, true
}

func SetScore(context *gin.Context, rule *globals.Rule) (bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Set Score action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	actionConfiguration, err := strconv.Atoi(*rule.ActionConfiguration)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	context.Set("violation_score", actionConfiguration)
	return false, true
}

func SetLevel(context *gin.Context, rule *globals.Rule) (bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Set Level action", rule.ID)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	actionConfiguration, err := strconv.Atoi(*rule.ActionConfiguration)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	context.Set("violation_level", uint(actionConfiguration))
	return false, true
}

func Report(target any, rule *globals.Rule) (bool, bool) {
	body := map[string]any{
		//
	}
	request, err := utils.NewHttp("post", "", body)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	response, err := request.Send()
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	if response.StatusCode != 200 {
		msg := fmt.Sprintf("Rule %d: Status code %d", rule.ID, response.StatusCode)
		errors.WriteErrorActionLog(msg)
		return true, false
	}
	return false, true
}

func SetVariable(context *gin.Context, rule *globals.Rule) (bool, bool) {
	options := strings.SplitN(*rule.ActionConfiguration, ",", 2)
	if len(options) != 2 {
		return true, false
	}
	context.Set(options[0], options[1])
	return false, true
}
