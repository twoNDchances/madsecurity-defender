package actions

import (
	"errors"
	"fmt"
	"madsecurity-defender/globals"
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

func Inspect(context *gin.Context, proxy *globals.Proxy, rule *globals.Rule, score *int) (bool, bool) {
	if rule.Severity == nil {
		msg := fmt.Sprintf("Rule %d missing Severity for Inspect action", rule.ID)
		context.Error(errors.New(msg))
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

func Request(context *gin.Context, target *globals.Target, rule *globals.Rule) (bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d missing Action Configuration for Request action", rule.ID)
		context.Error(errors.New(msg))
		return true, false
	}
	options := strings.Split(*rule.ActionConfiguration, ",")
	methods := globals.ListString{"post", "put", "patch", "delete"}
	if !slices.Contains(methods, options[0]) {
		msg := fmt.Sprintf("Rule %d: Method not in 'get', 'put', 'patch', 'delete' for Request action", rule.ID)
		context.Error(errors.New(msg))
		return true, false
	}
	if _, err := url.Parse(options[1]); err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		context.Error(errors.New(msg))
		return true, false
	}
	request, err := utils.NewHttp(options[0], options[1], nil)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		context.Error(errors.New(msg))
		return true, false
	}
	response, err := request.Send()
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		context.Error(errors.New(msg))
		return true, false
	}
	if response.StatusCode != 200 {
		msg := fmt.Sprintf("Rule %d: Status code %d", rule.ID, response.StatusCode)
		context.Error(errors.New(msg))
		return true, false
	}
	return false, true
}

func SetScore(context *gin.Context, rule *globals.Rule, score *int) (bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Set Score action", rule.ID)
		context.Error(errors.New(msg))
		return true, false
	}
	actionConfiguration, err := strconv.Atoi(*rule.ActionConfiguration)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		context.Error(errors.New(msg))
		return true, false
	}
	*score = actionConfiguration
	return false, true
}

func SetLevel(context *gin.Context, rule *globals.Rule, level *int) (bool, bool) {
	if rule.ActionConfiguration == nil {
		msg := fmt.Sprintf("Rule %d: missing Action Configuration for Set Level action", rule.ID)
		context.Error(errors.New(msg))
		return true, false
	}
	actionConfiguration, err := strconv.Atoi(*rule.ActionConfiguration)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		context.Error(errors.New(msg))
		return true, false
	}
	*level = actionConfiguration
	//
	return false, true
}

func Report(context *gin.Context, proxy *globals.Proxy, target *globals.Target, rule *globals.Rule) (bool, bool) {
	body := map[string]any{
		//
	}
	request, err := utils.NewHttp("post", "", body)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		context.Error(errors.New(msg))
		return true, false
	}
	response, err := request.Send()
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		context.Error(errors.New(msg))
		return true, false
	}
	if response.StatusCode != 200 {
		msg := fmt.Sprintf("Rule %d: Status code %d", rule.ID, response.StatusCode)
		context.Error(errors.New(msg))
		return true, false
	}
	return false, true
}
