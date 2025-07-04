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
)

func Allow() (bool, bool) {
	return true, true
}

func Deny() (bool, bool) {
	return true, false
}

func Inspect(proxy *globals.Proxy, rule *globals.Rule, score *int) (bool, bool) {
	if rule.Severity == nil {
		msg := fmt.Sprintf("Rule %d: missing Severity for Inspect action", rule.ID)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	switch *rule.Severity {
	case "notice":
		*score = *score + proxy.Severity.NOTICE
	case "warning":
		*score = *score + proxy.Severity.WARNING
	case "error":
		*score = *score + proxy.Severity.ERROR
	case "critical":
		*score = *score + proxy.Severity.CRITICAL
	}
	return false, true
}

func Request(proxy *globals.Proxy, target any, rule *globals.Rule) (bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Request action", rule.ID)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	options := strings.Split(*rule.ActionConfiguration, ",")
	methods := globals.ListString{"post", "put", "patch", "delete"}
	if !slices.Contains(methods, options[0]) {
		msg := fmt.Sprintf("Rule %d: Method not in 'get', 'put', 'patch', 'delete' for Request action", rule.ID)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	if _, err := url.Parse(options[1]); err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	body := globals.DictAny{
		// ""
	}
	request, err := utils.NewHttp(options[0], options[1], body)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	response, err := request.Send()
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	if response.StatusCode != 200 {
		msg := fmt.Sprintf("Rule %d: Status code %d", rule.ID, response.StatusCode)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	return false, true
}

func SetScore(proxy *globals.Proxy, rule *globals.Rule, score *int) (bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Set Score action", rule.ID)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	actionConfiguration, err := strconv.Atoi(*rule.ActionConfiguration)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	*score = actionConfiguration
	return false, true
}

func SetLevel(proxy *globals.Proxy, rule *globals.Rule, level *int) (bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Set Level action", rule.ID)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	actionConfiguration, err := strconv.Atoi(*rule.ActionConfiguration)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	*level = actionConfiguration
	//
	return false, true
}

func Report(proxy *globals.Proxy, target any, rule *globals.Rule) (bool, bool) {
	body := map[string]any{
		//
	}
	request, err := utils.NewHttp("post", "", body)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	response, err := request.Send()
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	if response.StatusCode != 200 {
		msg := fmt.Sprintf("Rule %d: Status code %d", rule.ID, response.StatusCode)
		errors.WriteErrorActionLog(proxy, msg)
		return true, false
	}
	return false, true
}
