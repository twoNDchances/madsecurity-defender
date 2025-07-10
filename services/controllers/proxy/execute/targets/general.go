package targets

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
)

func getValueFromPhase1Type(context *gin.Context, target *globals.Target) globals.DictString {
	raw := make(map[string][]string, 0)
	if target.Type == "header" {
		raw = context.Request.Header
	}
	if target.Type == "url.args" {
		raw = context.Request.URL.Query()
	}
	values := make(globals.DictString, 0)
	for key, value := range raw {
		values[strings.ToLower(key)] = strings.Join(value, ",")
	}
	return values
}

func getValueFromPhase2Type(context *gin.Context, target *globals.Target) globals.DictString {
	raw := make(map[string][]string, 0)
	if target.Type == "body" {

	}
	if target.Type == "file" {
		
	}
	values := make(globals.DictString, 0)
	for key, value := range raw {
		values[strings.ToLower(key)] = strings.Join(value, ",")
	}
	return values
}

func GetArrayTarget(context *gin.Context, target *globals.Target) globals.ListString {
	var needed globals.ListString
	if  target.Datatype == "array" && target.WordlistID != nil {
		switch target.Phase {
		case 1:
			words := make(globals.ListString, 0)
			for _, word := range globals.Words {
				if word.WordlistID == *target.WordlistID {
					words = append(words, word.Content)
				}
			}
			values := getValueFromPhase1Type(context, target)
			for _, word := range words {
				if value, ok := values[word]; ok {
					needed = append(needed, value)
				}
			}
		case 2:
		case 3:
		case 4:
		}
	}
	return needed
}

func GetNumberTarget(context *gin.Context, target *globals.Target) float64 {
	var needed float64
	if target.Datatype == "number" {
		switch target.Phase {
		case 1:
			values := getValueFromPhase1Type(context, target)
			if value, ok := values[target.Name]; ok {
				number, err := utils.ToFloat64(value)
				if err != nil {
					msg := fmt.Sprintf("Target %d: %v", target.ID, err)
					errors.WriteErrorTargetLog(msg)
				} else {
					needed = number
				}
			}
		case 2:
		case 3:
		case 4:
		}
	}
	return needed
}

func GetStringTarget(context *gin.Context, target *globals.Target) string {
	var needed string
	if target.Datatype == "string" {
		if target.Type == "getter" {
			needed = context.GetString(target.Name)
		} else {
			switch target.Phase {
			case 1:
				values := getValueFromPhase1Type(context, target)
				if value, ok := values[target.Name]; ok {
					needed = value
				}
			case 2:
			case 3:
			case 4:
			}
		}
	}
	return needed
}

func GetToRootTargets(context *gin.Context, targetId uint) []globals.Target {
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
