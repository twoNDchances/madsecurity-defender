package utils

import (
	"fmt"
	"log"
	"os"
	"time"
)

const TimeStampLayout = "15:04:05 - 02/01/2006"

func AppendToFile(path string, data string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(data); err != nil {
		return  err
	}
	return nil
}

func WriteAudit(auditPath, errorPath string, data string) {
	if err := AppendToFile(auditPath, fmt.Sprintf("%s\n", data)); err != nil {
		WriteError(errorPath, "[Proxy][Log][Audit]", err.Error())
	}
}

func WriteError(path, errorCauseName, data string) {
	textError := fmt.Sprintf("%s %s: %s\n",
		time.Now().Format(TimeStampLayout),
		errorCauseName,
		data,
	)
	if err := AppendToFile(path, textError); err != nil {
		msg := fmt.Sprintf("[Defender][Log][Error]: %v", err)
		log.Println(NewColor(msg, PURPLE))
	}
}
