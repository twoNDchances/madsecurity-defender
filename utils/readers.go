package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func ReadJson(path string, result any) error {
	data, err := ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, result); err != nil {
		return err
	}
	return nil
}

func CheckFileExists(path string) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func GetExtension(path string) string {
	return strings.ToLower(filepath.Ext(path))
}
