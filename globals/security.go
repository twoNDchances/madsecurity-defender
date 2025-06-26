package globals

import (
	"madsecurity-defender/utils"
	"net"
	"slices"

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
	if errors := Validate(
		s.validateUsername(),
		s.validatePassword(),
		s.validateManagerIp(),
		s.validateMaskType(),
		s.validateMaskHtml(),
		s.validateMaskJson(),
	); len(errors) > 0 {
		return errors
	}
	return nil
}

func (s *Security) validateUsername() error {
	if len(s.Username) == 0 {
		return utils.NewServerError("Security.Username", "Username is required when security enabled")
	}
	return nil
}

func (s *Security) validatePassword() error {
	if len(s.Password) < 8 {
		return utils.NewServerError("Security.Password", "Password length must be greater than or equal to 8 when security is enabled")
	}
	return nil
}

func (s *Security) validateManagerIp() error {
	if net.ParseIP(s.ManagerIp) == nil {
		return utils.NewServerError("Security.Manager.IP", "Invalid IP")
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
			return utils.NewServerError("Security.Mask.Type", "Must be 'html' or 'json'")
		}
	}
	return nil
}

func (s *Security) validateMaskHtml() error {
	if s.MaskStatus && s.MaskType == "html" {
		info, err := utils.CheckFileExists(s.MaskHtml)
		if err != nil {
			return utils.NewServerError("Security.Mask.Html", err.Error())
		}
		if info.IsDir() {
			return utils.NewServerError("Security.Mask.Html", "This path is directory, .html file is required")
		}
		if utils.GetExtension(s.MaskHtml) != ".html" {
			return utils.NewServerError("Security.MaskH.tml", "Extension is not a .html")
		}
	}
	return nil
}

func (s *Security) validateMaskJson() error {
	if s.MaskStatus && s.MaskType == "json" {
		info, err := utils.CheckFileExists(s.MaskJson)
		if err != nil {
			return utils.NewServerError("Security.Mask.Json", err.Error())
		}
		if info.IsDir() {
			return utils.NewServerError("Security.Mask.Json", "This path is directory, .json file is required")
		}
		if utils.GetExtension(s.MaskJson) != ".json" {
			return utils.NewServerError("Security.Mask.Json", "Extension is not a .json")
		}
		var result gin.H
		if err := utils.ReadJson(s.MaskJson, &result); err != nil {
			return utils.NewServerError("Security.Mask.Json", err.Error())
		}
	}
	return nil
}
