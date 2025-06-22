package globals

import (
	"madsecurity-defender/utils"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
)

type Security struct {
	Enable     bool
	Username   string
	Password   string
	ManagerIp  string
	MaskStatus bool
	MaskType   string
	MaskHtml   string
	MaskJson   string
}

func (s *Security) Validate() ListError {
	errors := make(ListError, 0)
	if err := s.validateUsername(); err != nil {
		errors = append(errors, err)
	}
	if err := s.validatePassword(); err != nil {
		errors = append(errors, err)
	}
	if err := s.validateManagerIp(); err != nil {
		errors = append(errors, err)
	}
	if err := s.validateMaskType(); err != nil {
		errors = append(errors, err)
	}
	if err := s.validateMaskHtml(); err != nil {
		errors = append(errors, err)
	}
	if err := s.validateMaskJson(); err != nil {
		errors = append(errors, err)
	}
	if len(errors) > 0 {
		return errors
	}
	return nil
}

func (s *Security) validateUsername() error {
	if s.Enable {
		if len(s.Username) == 0 {
			return utils.NewProxyError("Security.Username", "Username is required when security enabled")
		}
	}
	return nil
}

func (s *Security) validatePassword() error {
	if s.Enable {
		if len(s.Password) < 8 {
			return utils.NewProxyError("Security.Password", "Password length must be greater than or equal to 8 when security is enabled")
		}
	}
	return nil
}

func (s *Security) validateManagerIp() error {
	if net.ParseIP(s.ManagerIp) == nil {
		return utils.NewProxyError("Security.ManagerIp", "Invalid IP")
	}
	return nil
}

func (s *Security) validateMaskType() error {
	if s.MaskStatus {
		if !slices.Contains(
			ListString{
				"html",
				"json",
			},
			s.MaskType,
		) {
			return utils.NewProxyError("Security.MaskType", "Must be 'html' or 'json'")
		}
	}
	return nil
}

func (s *Security) validateMaskHtml() error {
	if s.MaskStatus && s.MaskType == "html" {
		info, err := os.Stat(s.MaskHtml)
		if err != nil {
			return utils.NewProxyError("Security.MaskHtml", err.Error())
		}
		if info.IsDir() {
			return utils.NewProxyError("Security.MaskHtml", "This path is directory, .html file is required")
		}
		ext := strings.ToLower(filepath.Ext(s.MaskHtml))
		if ext != ".html" {
			return utils.NewProxyError("Security.MaskHtml", "Extension is not a .html")
		}
	}
	return nil
}

func (s *Security) validateMaskJson() error {
	if s.MaskStatus && s.MaskType == "json" {
		info, err := os.Stat(s.MaskJson)
		if err != nil {
			return utils.NewProxyError("Security.MaskJson", err.Error())
		}
		if info.IsDir() {
			return utils.NewProxyError("Security.MaskJson", "This path is directory, .json file is required")
		}
		ext := strings.ToLower(filepath.Ext(s.MaskJson))
		if ext != ".json" {
			return utils.NewProxyError("Security.MaskJson", "Extension is not a .json")
		}
		var result gin.H
		if err := utils.ReadJson(s.MaskJson, &result); err != nil {
			return utils.NewProxyError("Security.MaskJson", err.Error())
		}
	}
	return nil
}
