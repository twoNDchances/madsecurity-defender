package utils

import (
	"fmt"
	"log"
	"os"
	"time"
)

const TimeStampLayout = "15:04:05 - 02/01/2006"

func AppendToFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return  err
	}
	return nil
}

func WriteAudit(auditPath, errorPath string, data []byte) {
	if err := AppendToFile(auditPath, []byte(string(data) + "\n")); err != nil {
		WriteError(errorPath, "[Proxy][Log][Audit]", err.Error())
	}
}

func WriteError(path, errorCauseName, data string) {
	textError := fmt.Sprintf("%s %s: %s",
		time.Now().Format(TimeStampLayout),
		errorCauseName,
		data,
	)
	if err := AppendToFile(path, []byte(textError)); err != nil {
		msg := fmt.Sprintf("[Defender][Log][Error]: %v", err)
		log.Println(NewColor(msg, PURPLE))
	}
}
