package utils

import (
	"encoding/json"
	"os"
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
