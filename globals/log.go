package globals

import (
	"madsecurity-defender/utils"
	"slices"
)

type Console struct {
	Enable    bool
	Type      string
	Separator string
}

type File struct {
	Enable    bool
	Name      string
	Type      string
	Separator string
}

type Log struct {
	Console Console
	File    File
}

func (l *Log) Validate() ListError {
	if errors := Validate(
		l.validateType("console"),
		l.validateType("file"),
		l.validateFileName(),
	); len(errors) > 0 {
		return errors
	}
	return nil
}

func (l *Log) validateType(logType string) error {
	if slices.Contains(
		ListString{
			"console",
			"file",
		},
		logType,
	) {
		if l.Console.Enable && !slices.Contains(
			ListString{
				"default",
				"json",
			},
			l.Console.Type,
		) {
			return utils.NewServerError("Log.Console.Type", "Must be 'default' or 'json'")
		}
		if l.File.Enable && !slices.Contains(
			ListString{
				"default",
				"json",
			},
			l.File.Type,
		) {
			return utils.NewServerError("Log.File.Type", "Must be 'default' or 'json'")
		}
	}
	return nil
}

func (l *Log) validateFileName() error {
	if !l.File.Enable {
		return nil
	}
	return utils.CheckAndCreateDefaultFile(l.File.Name, "Log.File.Name")
}
