package logistics

import (
	"encoding/json"
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type Logistic struct {
	Enable    bool
	Time      bool
	UserAgent bool
	ClientIP  bool
	Method    bool
	Path      bool
	Output    bool
	Target    bool
	Rule      bool
}

func (l *Logistic) build() globals.DictAny {
	data := make(globals.DictAny, 0)
	if l.Time {
		data["time"] = nil
	}
	if l.UserAgent {
		data["user_agent"] = nil
	}
	if l.ClientIP {
		data["client_ip"] = nil
	}
	if l.Method {
		data["method"] = nil
	}
	if l.Path {
		data["path"] = nil
	}
	if l.Output {
		data["output"] = nil
	}
	if l.Target {
		data["target"] = nil
	}
	if l.Rule {
		data["rule"] = nil
	}
	return data
}

func (l *Logistic) generate(context any, output any, targets *[]globals.Target, rule *globals.Rule) globals.DictAny {
	content := l.build()
	if l.Time {
		content["time"] = time.Now().Format(utils.TimeStampLayout)
	}
	switch ctx := context.(type) {
	case *gin.Context:
		if l.UserAgent {
			content["user_agent"] = ctx.Request.UserAgent()
		}
		if l.ClientIP {
			content["client_ip"] = ctx.RemoteIP()
		}
		if l.Method {
			content["method"] = ctx.Request.Method
		}
		if l.Path {
			content["path"] = ctx.Request.URL.Path
		}
	case *http.Response:
		if l.UserAgent {
			content["user_agent"] = ctx.Request.UserAgent()
		}
		if l.ClientIP {
			content["client_ip"] = ctx.Request.RemoteAddr
		}
		if l.Method {
			content["method"] = ctx.Request.Method
		}
		if l.Path {
			content["path"] = ctx.Request.URL.Path
		}
	}
	if l.Output {
		content["output"] = output
	}
	if l.Target {
		var targetValues []globals.DictAny
		for _, target := range *targets {
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
		content["target"] = targetValues
	}
	if l.Rule {
		content["rule"] = globals.DictAny{
			"name": rule.Name,
			"alias": rule.Alias,
			"comparator": rule.Comparator,
			"inverse": rule.Inverse,
			"value": rule.Value,
			"wordlist_id": rule.WordlistID,
			"action": rule.Action,
			"action_configuration": rule.ActionConfiguration,
			"severity": rule.Severity,
		}
	}
	return content
}

func (l *Logistic) Write(context any, output any, targets *[]globals.Target, rule *globals.Rule) error {
	if l.Enable {
		content := l.generate(context, output, targets, rule)
		data, err := json.Marshal(content)
		if err != nil {
			return err
		}
		auditPath := fmt.Sprintf("%s.json", globals.ProxyConfigs.HistoryAuditPath)
		errorPath := fmt.Sprintf("%s.log", globals.ProxyConfigs.HistoryErrorPath)
		utils.WriteAudit(auditPath, errorPath, string(data))
	}
	return nil
}

func NewLogistic(rule *globals.Rule) *Logistic {
	logistic := Logistic{
		Enable:    rule.Log,
		Time:      rule.Time,
		UserAgent: rule.UserAgent,
		ClientIP:  rule.ClientIP,
		Method:    rule.Method,
		Path:      rule.Path,
		Output:    rule.Output,
		Target:    rule.Target,
		Rule:      rule.Rule,
	}
	return &logistic
}
