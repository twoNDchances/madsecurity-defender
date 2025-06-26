package globals

import (
	"fmt"
	"madsecurity-defender/utils"
	"os"
	"path/filepath"
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
	if l.File.Enable {
		path := filepath.Dir(l.File.Name)
		info, err := utils.CheckFileExists(path)
		if err != nil {
			return utils.NewServerError("Log.File.Name", err.Error())
		}
		if !info.IsDir() {
			return utils.NewServerError("Log.File.Name", fmt.Sprintf("%s is not a directory", path))
		}
		file, err := os.Create(l.File.Name)
		if err != nil {
			return utils.NewServerError("Log.File.Name", err.Error())
		}
		defer file.Close()
	}
	return nil
}
