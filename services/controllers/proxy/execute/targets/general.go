package targets

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase1"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase2"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase3"
	"madsecurity-defender/utils"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
)

func getValueFromPhase1Type(context *gin.Context, target *globals.Target) globals.DictString {
	raw := make(map[string][]string, 0)
	if target.Type == "header" {
		raw = phase1.GetHeaderData(context)
	}
	if target.Type == "url.args" {
		raw = phase1.GetUrlArgsData(context)
	}
	values := make(globals.DictString, 0)
	for key, value := range raw {
		values[strings.ToLower(key)] = strings.Join(value, ",")
	}
	return values
}

func getValueFromPhase2Type(context *gin.Context, target *globals.Target) globals.DictString {
	values := make(globals.DictString, 0)
	if target.Type == "body" {
		_, _, values = phase2.GetBodyData(context, target.ID)
	}
	if target.Type == "file" {
		_, _, values, _, _, _ = phase2.GetFileData(context, target.ID)
	}
	return values
}

func getValueFromPhase3Type(context *http.Response, target *globals.Target) globals.DictString {
	raw := make(map[string][]string, 0)
	if target.Type == "header" {
		raw = phase3.GetHeaderData(context)
	}
	values := make(globals.DictString, 0)
	for key, value := range raw {
		values[strings.ToLower(key)] = strings.Join(value, ",")
	}
	return values
}

func getValueFromPhase4Type(context *http.Response, target *globals.Target) globals.DictString {
	values := make(globals.DictString, 0)
	//
	return values
}

func GetArrayTarget(context any, target *globals.Target) globals.ListString {
	var needed globals.ListString
	if  target.Datatype == "array" && target.WordlistID != nil {
		words := make(globals.ListString, 0)
		for _, word := range globals.Words {
			if word.WordlistID == *target.WordlistID {
				words = append(words, word.Content)
			}
		}
		var values globals.DictString
		switch ctx := context.(type) {
		case *gin.Context:
			switch target.Phase {
			case 1:
				values = getValueFromPhase1Type(ctx, target)
			case 2:
				values = getValueFromPhase2Type(ctx, target)
			}
		case *http.Response:
			switch target.Phase {
			case 3:
				values = getValueFromPhase3Type(ctx, target)
			case 4:
				values = getValueFromPhase4Type(ctx, target)
			}
		}
		for _, word := range words {
			if value, ok := values[word]; ok {
				needed = append(needed, value)
			}
		}
	}
	return needed
}

func GetNumberTarget(context any, target *globals.Target) float64 {
	var needed float64
	if target.Datatype == "number" {
		var values globals.DictString
		switch ctx := context.(type) {
		case *gin.Context:
			switch target.Phase {
			case 1:
				values = getValueFromPhase1Type(ctx, target)
			case 2:
				values = getValueFromPhase2Type(ctx, target)
			}
		case *http.Response:
			switch target.Phase {
			case 3:
				values = getValueFromPhase3Type(ctx, target)
			case 4:
				values = getValueFromPhase4Type(ctx, target)
			}
		}
		if value, ok := values[target.Name]; ok {
			number, err := utils.ToFloat64(value)
			if err != nil {
				msg := fmt.Sprintf("Target %d: %v", target.ID, err)
				errors.WriteErrorTargetLog(msg)
			} else {
				needed = number
			}
		}
	}
	return needed
}

func GetStringTarget(context any, contextGin *gin.Context, target *globals.Target) string {
	var needed string
	if target.Datatype == "string" {
		if target.Type == "getter" {
			needed = contextGin.GetString(target.Name)
		} else {
			var values globals.DictString
			switch ctx := context.(type) {
			case *gin.Context:
				switch target.Phase {
				case 1:
					values = getValueFromPhase1Type(ctx, target)
				case 2:
					values = getValueFromPhase2Type(ctx, target)
				}
			case *http.Response:
				switch target.Phase {
				case 3:
					values = getValueFromPhase3Type(ctx, target)
				case 4:
					values = getValueFromPhase4Type(ctx, target)
				}
			}
			if value, ok := values[target.Name]; ok {
				needed = value
			}
		}
	}
	return needed
}

func GetToRootTargets(targetId uint) []globals.Target {
	visited := make(map[uint]bool)
	path := make([]globals.Target, 0)
	currentId := targetId
	for {
		node, exists := globals.Targets[currentId]
		if !exists {
			break
		}
		path = append(path, node)
		if visited[currentId] {
			break
		}
		visited[currentId] = true
		if node.TargetID == nil {
			break
		}
		nextId := *node.TargetID
		if nextId == currentId {
			break
		}
		if visited[nextId] {
			break
		}
		if _, ok := globals.Targets[nextId]; !ok {
			break
		}
		currentId = nextId
	}
	slices.Reverse(path)
	return path
}
