package utils

import (
	"encoding/json"
	"fmt"
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

func CheckAndCreateDefaultFile(path, errorCauseName string) error {
	dir := filepath.Dir(path)
	info, err := CheckFileExists(dir)
	if err != nil {
		return NewProxyError(errorCauseName, err.Error())
	}
	if !info.IsDir() {
		return NewProxyError(errorCauseName, fmt.Sprintf("%s is not a directory", dir))
	}
	if _, err := CheckFileExists(path); os.IsNotExist(err) {
		file, err := os.Create(path)
		if err != nil {
			return NewProxyError(errorCauseName, err.Error())
		}
		defer file.Close()
	}
	return nil
}
