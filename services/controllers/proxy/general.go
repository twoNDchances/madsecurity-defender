package request

import (
	"madsecurity-defender/globals"
	"slices"

	"github.com/gin-gonic/gin"
)

func GetRuleByGroups(context *gin.Context, proxy *globals.Proxy) []globals.Rule {
	level := proxy.ViolationLevel
	rules := make([]globals.Rule, 0)
	for _, group := range globals.Groups {
		if group.Level != uint(level){
			continue
		}
		for _, rule := range globals.Rules {
			if slices.Contains(group.Rules, rule.ID) &&
			(slices.Contains([]uint8{0,1}, rule.Phase)) {
				rules = append(rules, rule)
			}
		}
	}
	return rules
}

func Enumurate(context *gin.Context, proxy *globals.Proxy) {
	rules := GetRuleByGroups(context, proxy)
	for range rules {

	}
}

func Execute(context *gin.Context, rule globals.Rule)  {
	
}
