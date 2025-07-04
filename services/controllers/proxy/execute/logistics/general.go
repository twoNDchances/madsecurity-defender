package logistics

import (
	"encoding/json"
	"fmt"
	"log"
	"madsecurity-defender/globals"
	"net/http"
	"os"
	"strings"
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

func (l *Logistic) build() string {
	data := make(globals.DictAny, 0)
	if l.Time {
		data["time"] = `"timeValue"`
	}
	if l.UserAgent {
		data["user_agent"] = `"userAgentValue"`
	}
	if l.ClientIP {
		data["client_ip"] = `"clientIPValue"`
	}
	if l.Method {
		data["method"] = `"methodValue"`
	}
	if l.Path {
		data["path"] = `"pathValue"`
	}
	if l.Output {
		data["output"] = `"outputValue"`
	}
	if l.Target {
		data["target"] = `"targetValue"`
	}
	if l.Rule {
		data["rule"] = `"ruleValue"`
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return "{}"
	}
	return string(bytes)
}

func (l *Logistic) generate(context any, output any, targets *[]globals.Target, rule *globals.Rule) string {
	content := l.build()
	if l.Time {
		content = strings.ReplaceAll(content, "timeValue", time.Now().String())
	}
	switch ctx := context.(type) {
	case *gin.Context:
		if l.UserAgent {
			content = strings.ReplaceAll(content, "userAgentValue", ctx.Request.UserAgent())
		}
		if l.ClientIP {
			content = strings.ReplaceAll(content, "clientIPValue", ctx.RemoteIP())
		}
		if l.Method {
			content = strings.ReplaceAll(content, "methodValue", ctx.Request.Method)
		}
		if l.Path {
			content = strings.ReplaceAll(content, "pathValue", ctx.Request.URL.Path)
		}
	case *http.Response:
		if l.UserAgent {
			content = strings.ReplaceAll(content, "userAgentValue", ctx.Request.UserAgent())
		}
		if l.ClientIP {
			content = strings.ReplaceAll(content, "clientIPValue", ctx.Request.RemoteAddr)
		}
		if l.Method {
			content = strings.ReplaceAll(content, "methodValue", ctx.Request.Method)
		}
		if l.Path {
			content = strings.ReplaceAll(content, "pathValue", ctx.Request.URL.Path)
		}
	}
	if l.Output {
		content = strings.ReplaceAll(content, "outputValue", fmt.Sprint(output))
	}
	if l.Target {
		var targetValue globals.ListString
		for _, target := range *targets {
			var (
				engine = "null"
				engineConfiguration = "null"
			)
			if target.Engine != nil {
				engine = fmt.Sprintf(`"%s"`, *target.Engine)
			}
			if target.EngineConfiguration != nil {
				engineConfiguration = fmt.Sprintf(`"%s"`, *target.EngineConfiguration)
			}
			data := fmt.Sprintf(
				`{"name":"%s","alias":"%s","type":"%s","engine":%s,"engineConfiguration":%s}`,
				target.Name, target.Alias, target.Type, engine, engineConfiguration,
			)
			targetValue = append(targetValue, data)
		}
		content = strings.ReplaceAll(content, `"targetValue"`, fmt.Sprintf("[%s]", strings.Join(targetValue, ",")))
	}
	if l.Rule {
		var (
			value = "null"
			wordlistId any = "null"
			action = "null"
			severity = "null"
		)
		if rule.Value != nil {
			value = fmt.Sprintf(`"%s"`, *rule.Value)
		}
		if rule.WordlistID != nil {
			wordlistId = *rule.WordlistID
		}
		if rule.Action != nil {
			action = fmt.Sprintf(`"%s"`, *rule.Action)
		}
		if rule.Severity != nil {
			severity = fmt.Sprintf(`"%s"`, *rule.Severity)
		}
		ruleValue := fmt.Sprintf(
			`{"name":"%s","alias":"%s","comparator":"%s","inverse":%v,"value":%s,"wordlistId":%v,"action":%s,"severity":%s}`,
			rule.Name, rule.Alias, rule.Comparator, rule.Inverse, value, wordlistId, action, severity,
		)
		content = strings.ReplaceAll(content, `"ruleValue"`, ruleValue)
	}
	return content
}

func (l *Logistic) Write(context any, path string, output any, targets *[]globals.Target, rule *globals.Rule) bool {
	if !l.Enable {
		return true
	}
	content := l.generate(context, output, targets, rule)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		// msg := fmt.Sprintf("Rule")
		// context.Error()
		log.Println(err)
		return false
	}
	return true
}

func NewLogistic(enable, time, userAgent, clientIp, method, path, output, target, rule bool) *Logistic {
	logistic := Logistic{
		Enable:    enable,
		Time:      time,
		UserAgent: userAgent,
		ClientIP:  clientIp,
		Method:    method,
		Path:      path,
		Output:    output,
		Target:    target,
		Rule:      rule,
	}
	return &logistic
}
